'use client';

import { useState, useEffect } from 'react';

interface Module {
  name: string;
  description: string;
  severity: string;
}

export default function Home() {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8000/api/v1/attacks/test-sqli?id=1');
  const [selectedModule, setSelectedModule] = useState('SQL Injection');
  const [modules, setModules] = useState<Module[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  // Carregar módulos disponíveis
  useEffect(() => {
    fetch('http://localhost:8000/api/v1/attacks/modules')
      .then(res => res.json())
      .then(data => setModules(data.modules || []))
      .catch(err => console.error('Error loading modules:', err));
  }, []);

  const runScan = async () => {
    if (!targetUrl) {
      alert('Por favor, insira uma URL alvo');
      return;
    }

    setLoading(true);
    setResult(null);
    
    try {
      const url = `http://localhost:8000/api/v1/attacks/test?target_url=${encodeURIComponent(targetUrl)}&module_name=${encodeURIComponent(selectedModule)}`;
      
      const response = await fetch(url, { method: 'POST' });
      const data = await response.json();
      setResult(data);
    } catch (error) {
      alert('Erro ao executar scan: ' + (error as Error).message);
      setResult({ error: (error as Error).message });
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      'critical': 'text-red-600 bg-red-100',
      'high': 'text-orange-600 bg-orange-100',
      'medium': 'text-yellow-600 bg-yellow-100',
      'low': 'text-blue-600 bg-blue-100',
      'info': 'text-gray-600 bg-gray-100',
    };
    return colors[severity] || 'text-gray-600 bg-gray-100';
  };

  const getStatusColor = (success: boolean) => {
    return success ? 'text-red-400' : 'text-green-400';
  };

  return (
    <main className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 text-white">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-12">
          <h1 className="text-6xl font-bold mb-4 bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">
            AttackSim
          </h1>
          <p className="text-xl text-gray-300">
            Plataforma de Simulação de Ataques Controlados
          </p>
        </div>

        <div className="max-w-4xl mx-auto">
          {/* Painel de Módulos */}
          <div className="bg-gray-800 rounded-lg p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4 text-orange-400">
              📦 Módulos Disponíveis
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {modules.map((mod) => (
                <div
                  key={mod.name}
                  onClick={() => setSelectedModule(mod.name)}
                  className={`p-4 rounded-lg cursor-pointer transition-all ${
                    selectedModule === mod.name
                      ? 'bg-orange-600 border-2 border-orange-400'
                      : 'bg-gray-700 border-2 border-transparent hover:bg-gray-600'
                  }`}
                >
                  <div className="font-semibold">{mod.name}</div>
                  <div className="text-sm text-gray-300 mt-1">{mod.description}</div>
                  <span className={`inline-block mt-2 px-2 py-1 rounded text-xs font-medium ${getSeverityColor(mod.severity)}`}>
                    {mod.severity.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Scan Configuration */}
          <div className="bg-gray-800 rounded-lg p-6 shadow-2xl">
            <h2 className="text-2xl font-semibold mb-6 text-orange-400">
              🎯 Configurar Scan
            </h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2 text-gray-300">
                  Módulo Selecionado
                </label>
                <select
                  value={selectedModule}
                  onChange={(e) => setSelectedModule(e.target.value)}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-orange-500 text-white"
                >
                  {modules.map((mod) => (
                    <option key={mod.name} value={mod.name}>
                      {mod.name} - {mod.description}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2 text-gray-300">
                  URL Alvo
                </label>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="http://localhost:8000/api/v1/attacks/test-sqli?id=1"
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-orange-500 text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-2 text-sm text-gray-400">
                <div>💉 SQLi: /test-sqli?id=1</div>
                <div>📝 XSS: /test-xss?name=Test</div>
                <div>📁 Traversal: /test-traversal?file=test.txt</div>
                <div>🎯 All: /test-all?param=1</div>
              </div>

              <button
                onClick={runScan}
                disabled={loading}
                className="w-full bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 text-white font-semibold py-3 px-6 rounded-lg transition duration-200"
              >
                {loading ? '⏳ Executando Scan...' : `🚀 Executar ${selectedModule}`}
              </button>
            </div>

            {/* Results */}
            {result && (
              <div className="mt-8 p-6 bg-gray-900 rounded-lg border border-gray-700">
                <h3 className="text-xl font-semibold mb-4 text-green-400">
                  📊 Resultado do Scan
                </h3>
                
                <div className="space-y-2">
                  {result.error ? (
                    <p className="text-red-400">❌ Erro: {result.error}</p>
                  ) : (
                    <>
                      <p><span className="text-gray-400">Módulo:</span> {result.module || selectedModule}</p>
                      <p><span className="text-gray-400">Alvo:</span> {result.target || targetUrl}</p>
                      
                      {result.result ? (
                        <>
                          <p>
                            <span className="text-gray-400">Status:</span>{' '}
                            <span className={getStatusColor(result.result.success)}>
                              {result.result.success ? '⚠️ VULNERABILIDADE ENCONTRADA' : '✅ Nenhuma Vulnerabilidade'}
                            </span>
                          </p>
                          <p>
                            <span className="text-gray-400">Severidade:</span>{' '}
                            <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(result.result.severity)}`}>
                              {result.result.severity?.toUpperCase() || 'N/A'}
                            </span>
                          </p>
                          <p><span className="text-gray-400">Detalhes:</span> {result.result.details || 'N/A'}</p>
                          
                          {result.result.remediation && (
                            <p><span className="text-gray-400">🔧 Correção:</span> {result.result.remediation}</p>
                          )}
                          
                          {result.result.findings && result.result.findings.length > 0 && (
                            <div className="mt-4">
                              <p className="text-gray-400 mb-2">🎯 Descobertas ({result.result.findings.length}):</p>
                              <div className="space-y-2">
                                {result.result.findings.slice(0, 3).map((finding: any, idx: number) => (
                                  <div key={idx} className="bg-gray-950 p-3 rounded">
                                    <p><span className="text-orange-400">Payload:</span> {finding.payload}</p>
                                    <p><span className="text-gray-500 text-sm">{finding.evidence}</span></p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </>
                      ) : (
                        <p className="text-yellow-400">Resultado não disponível</p>
                      )}
                    </>
                  )}
                  
                  <details className="mt-4">
                    <summary className="cursor-pointer text-gray-500 text-sm">🔍 Ver resposta bruta (debug)</summary>
                    <pre className="bg-gray-950 p-4 rounded-lg overflow-x-auto text-xs mt-2">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  </details>
                </div>
              </div>
            )}
          </div>

          <div className="mt-8 text-center text-gray-400 text-sm">
            <p>⚡ Ataques executados em ambiente sandbox isolado</p>
            <p className="mt-2">🔒 Use apenas em sistemas que você tem autorização para testar</p>
          </div>
        </div>
      </div>
    </main>
  );
}
