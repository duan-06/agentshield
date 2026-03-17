import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store/authStore';
import Navbar from './components/Navbar';
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import TryExamplePage from './pages/TryExamplePage';
import BringYourOwnPage from './pages/BringYourOwnPage';

function App() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  return (
    <Router>
      <Navbar />
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/try-example"
          element={isAuthenticated ? <TryExamplePage /> : <Navigate to="/login" />}
        />
        <Route
          path="/bring-your-own"
          element={isAuthenticated ? <BringYourOwnPage /> : <Navigate to="/login" />}
        />
      </Routes>
    </Router>
  );
}

export default App;
