import React from "react";
import { Link } from "react-router-dom";

export default function Navbar() {
  return (
    <nav className="bg-gray-900 text-white px-6 py-4 flex justify-between items-center">
      <h1 className="text-xl font-bold">Meu Site</h1>
      <div className="flex gap-6">
        <Link to="/" className="hover:text-blue-400 transition">
          Home
        </Link>
        <Link to="/perfil" className="hover:text-blue-400 transition">
          Perfil
        </Link>
      </div>
    </nav>
  );
}
