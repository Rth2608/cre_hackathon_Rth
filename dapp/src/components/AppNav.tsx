import { Link } from "react-router-dom";

interface AppNavProps {
  current: "submit" | "verify" | "result" | "por";
}

export default function AppNav({ current }: AppNavProps) {
  return (
    <nav className="top-nav" aria-label="primary">
      <Link to="/" className={current === "submit" ? "nav-link active" : "nav-link"}>
        Request
      </Link>
      <Link to="/verify" className={current === "verify" || current === "result" ? "nav-link active" : "nav-link"}>
        Verify
      </Link>
      <Link to="/por" className={current === "por" ? "nav-link active" : "nav-link"}>
        PoR Dashboard
      </Link>
    </nav>
  );
}
