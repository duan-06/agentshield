import torch
import json
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments, ProgressCallback, TrainerCallback
from datasets import Dataset
import numpy as np
from tqdm import tqdm

# 1. 加载现有模型和分词器
model_path = "/workspace/back/src/Llama Shield/models/meta-llama--Llama-Prompt-Guard-2-86M"
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)

# 2. 加载中文数据集 (JSONL 格式)
data_path = "/workspace/test/dataset/test.jsonl"
data = []
with open(data_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            data.append(json.loads(line))

print(f"总共加载 {len(data)} 条样本")

# 统计标签分布
from collections import Counter
label_counts = Counter(item["label"] for item in data)
print(f"标签分布: {dict(label_counts)}")

# 数据集标签映射: 违规 -> MALICIOUS(1), 不违规 -> BENIGN(0)
label_map = {"不违规": 0, "BENIGN": 0, "违规": 1, "MALICIOUS": 1}

def preprocess(example):
    encoded = tokenizer(
        example["text"],
        truncation=True,
        padding="max_length",
        max_length=512,
    )
    raw_label = example.get("label", "")
    encoded["label"] = label_map.get(raw_label, 0)
    return encoded

# 构建数据集并做预处理
dataset = Dataset.from_list(data)
dataset = dataset.map(preprocess, remove_columns=["text", "label", "subject"])

# 划分训练集和验证集 (90% / 10%)
dataset_split = dataset.train_test_split(test_size=0.1, seed=42)
train_dataset = dataset_split["train"]
val_dataset = dataset_split["test"]
# 预转为 torch tensor，避免训练时逐条转换开销
train_dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "label"])
val_dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "label"])
print(f"训练集: {len(train_dataset)} 条, 验证集: {len(val_dataset)} 条")

# 3. 设置训练参数
training_args = TrainingArguments(
    output_dir="./fine_tuned_prompt_guard",
    num_train_epochs=3,
    per_device_train_batch_size=16,       # 增大 batch size
    per_device_eval_batch_size=32,         # 增大 eval batch size
    learning_rate=2e-5,
    weight_decay=0.01,
    save_strategy="epoch",
    eval_strategy="epoch",
    load_best_model_at_end=True,
    metric_for_best_model="f1",
    logging_steps=100,
    fp16=True,                             # 混合精度训练，显存减半、速度提升 30-60%
    gradient_accumulation_steps=2,         # 梯度累积，等效 batch_size=32
    dataloader_num_workers=4,              # 多线程预加载数据
    dataloader_pin_memory=True,            # 数据锁页内存加速 GPU 传输
    optim="adamw_torch_fused",             # 融合 AdamW，比原生快 10-20%
)

# 定义评估指标
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    acc = accuracy_score(labels, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary")
    return {"accuracy": acc, "precision": precision, "recall": recall, "f1": f1}

# 自定义 Tqdm 进度条回调
class TqdmCallback(TrainerCallback):
    def __init__(self):
        self.training_bar = None
        self.epoch_bar = None

    def on_train_begin(self, args, state, control, **kwargs):
        total_steps = state.max_steps
        self.training_bar = tqdm(
            total=total_steps,
            desc="Training",
            unit="step",
            dynamic_ncols=True,
        )

    def on_train_end(self, args, state, control, **kwargs):
        if self.training_bar:
            self.training_bar.close()
            self.training_bar = None
        if self.epoch_bar:
            self.epoch_bar.close()
            self.epoch_bar = None

    def on_step_begin(self, args, state, control, **kwargs):
        if self.training_bar:
            postfix = {}
            if state.log_history:
                last_log = state.log_history[-1]
                for key in ["loss", "learning_rate"]:
                    if key in last_log:
                        postfix[key] = f"{last_log[key]:.4f}"
            self.training_bar.set_postfix(postfix)

    def on_step_end(self, args, state, control, **kwargs):
        if self.training_bar:
            self.training_bar.update(1)

    def on_epoch_begin(self, args, state, control, **kwargs):
        self.epoch_bar = tqdm(
            desc=f"Epoch {int(state.epoch) + 1}/{args.num_train_epochs}",
            unit="batch",
            dynamic_ncols=True,
        )

    def on_epoch_end(self, args, state, control, **kwargs):
        if self.epoch_bar:
            self.epoch_bar.close()
            self.epoch_bar = None

# 4. 开始训练（带进度条）
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    compute_metrics=compute_metrics,
)

# 使用 tqdm 进度条替代默认日志
trainer.remove_callback(ProgressCallback)
trainer.add_callback(TqdmCallback)

print("\n开始训练...\n")
trainer.train()

# 最终验证结果
print("\n===== 最终验证结果 =====")
final_metrics = trainer.evaluate()
for k, v in final_metrics.items():
    print(f"  {k}: {v:.4f}")

# 5. 保存微调后的模型
output_dir = "./fine_tuned_prompt_guard"
trainer.save_model(output_dir)
tokenizer.save_pretrained(output_dir)
print(f"\n微调完成！模型已保存到: {output_dir}")
