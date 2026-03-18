# -*- coding: utf-8 -*-
"""
清除 main.py 中所有 audit_logger 调用块
"""

path = r'app/main.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

print(f"Before: {content.count('audit_logger')} occurrences")

# 删除 log_blocked_request 调用块（输入扫描阻断）
content = content.replace(
    """            # 记录阻断日志
            await audit_logger.log_blocked_request(
                request_id=request_id,
                messages=messages_dict,
                blocked_by=input_scan_result.blocked_by,
                reason=input_scan_result.blocked_reason,
                scan_result=input_scan_result
            )

            # 更新指标""",
    """            # 更新指标"""
)

# 删除 log_blocked_request 调用块（输出扫描阻断）
content = content.replace(
    """            await audit_logger.log_blocked_request(
                request_id=request_id,
                messages=messages_dict,
                response=response_content,
                blocked_by=output_scan_result.blocked_by,
                reason=output_scan_result.blocked_reason,
                scan_result=output_scan_result
            )

            metrics.increment_blocked_requests(""",
    """            metrics.increment_blocked_requests("""
)

# 删除 log_successful_request 调用块
content = content.replace(
    """        # 记录成功请求
        await audit_logger.log_successful_request(
            request_id=request_id,
            messages=messages_dict,
            response=response_content,
            input_scan=input_scan_result,
            output_scan=output_scan_result,
            duration=duration
        )

        # 更新指标""",
    """        # 更新指标"""
)

# 如果还有残留，直接删除整行
lines = content.splitlines(keepends=True)
cleaned = []
for line in lines:
    if 'audit_logger' in line:
        print(f"  Removing residual line: {line.rstrip()}")
    else:
        cleaned.append(line)
content = ''.join(cleaned)

print(f"After: {content.count('audit_logger')} occurrences")

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Done!")
