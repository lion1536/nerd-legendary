
import React from "react";

export default function Perfil() {
  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center p-6">
      <header className="w-full max-w-4xl bg-white shadow-md rounded-xl p-4 flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-800">Meu Perfil</h1>
        <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition">
          Editar
        </button>
      </header>
      <section className="w-full max-w-4xl bg-white mt-6 shadow-md rounded-xl p-6 flex flex-col md:flex-row items-center gap-6">
        <img
          src="https://via.placeholder.com/150"
          alt="Foto de Perfil"
          className="w-32 h-32 rounded-full object-cover shadow"
        />
        <div className="flex-1">
          <h2 className="text-xl font-semibold text-gray-800">Nome do Usuário</h2>
          <p className="text-gray-600">email@exemplo.com</p>
          <p className="text-gray-500 mt-2">Descrição curta ou bio do usuário</p>
        </div>
      </section>
      <section className="w-full max-w-4xl bg-white mt-6 shadow-md rounded-xl p-6">
        <h3 className="text-lg font-semibold text-gray-800 mb-4">Informações</h3>
        <ul className="space-y-2">
          <li><span className="font-medium">Idade:</span> 25 anos</li>
          <li><span className="font-medium">Cidade:</span> Pato Branco - PR</li>
          <li><span className="font-medium">Profissão:</span> Desenvolvedor</li>
        </ul>
      </section>
      <section className="w-full max-w-4xl mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white shadow-md rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-2">Projetos</h3>
          <p className="text-gray-600">Lista ou resumo dos projetos...</p>
        </div>
        <div className="bg-white shadow-md rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-2">Conquistas</h3>
          <p className="text-gray-600">Medalhas, badges ou reconhecimentos...</p>
        </div>
      </section>
    </div>
  );
}
