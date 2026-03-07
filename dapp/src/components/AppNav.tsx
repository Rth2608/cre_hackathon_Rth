import { Link } from "react-router-dom";

interface AppNavProps {
  current: "submit" | "verify" | "result" | "por";
}

export default function AppNav({ current }: AppNavProps) {
  return (
    <nav className="top-nav" aria-label="primary">
      <Link to="/" className={current === "submit" || current === "result" ? "nav-link active" : "nav-link"}>
        Request
      </Link>
    </nav>
  );
}
