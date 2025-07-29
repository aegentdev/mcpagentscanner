import { useState, useEffect } from 'react';
import AppLayout from '@/components/layout/AppLayout';
import SystemMetrics from '@/components/dashboard/SystemMetrics';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { RefreshCw, AlertTriangle, CheckCircle } from 'lucide-react';



interface ScanResult {
  success: boolean;
  file_path?: string;
  constraints_count?: number;
  risks_count?: number;
  constraints?: any[];
  risks?: any[];
  hardened_code?: string[];
  message?: string;
  error?: string;
  timestamp?: string;
  scan_id?: number;
}

const Dashboard = () => {
  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);

  // Update system overview based on scan results
  const updatedSystemOverview = {
    totalScans: scanHistory.length,
    totalCritical: scanHistory.reduce((total, scan) => 
      total + (scan.risks?.filter((r: any) => r.severity === 'critical').length || 0), 0),
    totalMedium: scanHistory.reduce((total, scan) => 
      total + (scan.risks?.filter((r: any) => r.severity === 'medium').length || 0), 0),
    highRiskCount: scanResults?.risks?.filter((r: any) => r.severity === 'critical').length || 0
  };

  // Fetch scan results from the Flask backend
  const fetchScanResults = async () => {
    try {
      const response = await fetch('/api/results');
      const data = await response.json();
      if (data && Object.keys(data).length > 0) {
        setScanResults(data);
      }
    } catch (error) {
      console.error('Error fetching scan results:', error);
    }
  };

  // Fetch scan history
  const fetchScanHistory = async () => {
    try {
      const response = await fetch('/api/history');
      const data = await response.json();
      setScanHistory(data);
    } catch (error) {
      console.error('Error fetching scan history:', error);
    }
  };

  // Refresh data
  const refreshData = async () => {
    setIsLoading(true);
    await Promise.all([fetchScanResults(), fetchScanHistory()]);
    setIsLoading(false);
  };

  // Handle scan selection
  const handleScanClick = (scan: any) => {
    setSelectedScan(scan);
  };

  // Close selected scan
  const closeSelectedScan = () => {
    setSelectedScan(null);
  };

  useEffect(() => {
    fetchScanResults();
    fetchScanHistory();
    
    // Set up polling for real-time updates
    const interval = setInterval(() => {
      fetchScanResults();
      fetchScanHistory();
    }, 5000);

    return () => clearInterval(interval);
  }, []);



  const riskItems = scanResults?.risks?.slice(0, 3).map((risk: any) => ({
    title: risk.description,
    description: risk.impact || 'Security risk detected',
    severity: risk.severity
  })) || [
    {
      title: 'No risks detected',
      description: 'Run a security scan to identify potential risks',
      severity: 'low'
    }
  ];





  const getRiskSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-blue-500';
    }
  };

  return (
    <AppLayout latestScanTime={scanResults?.timestamp || scanHistory[0]?.timestamp}>
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex flex-col gap-2">
            <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
            <p className="text-muted-foreground">
              Overview of your multi-agent system security status
            </p>
          </div>
          <button
            onClick={refreshData}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
          >
            <RefreshCw size={16} className={isLoading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
        
        <SystemMetrics data={updatedSystemOverview} />
        

        
        {/* Tabs Section */}
        <Tabs defaultValue="recent-activity">
          <TabsList className="grid w-full md:w-[400px] grid-cols-2">
            <TabsTrigger value="recent-activity">Recent Activity</TabsTrigger>
            <TabsTrigger value="risk-summary">Risk Summary</TabsTrigger>
          </TabsList>
          
          <TabsContent value="recent-activity" className="mt-4 space-y-4">
            {/* Recent Activity content removed as requested */}
          </TabsContent>
          
          <TabsContent value="risk-summary" className="mt-4 space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Risk Summary</CardTitle>
                <CardDescription>
                  Overview of current system risks
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {riskItems.map((item, index) => (
                    <div key={index} className="flex items-start gap-4 pb-4 border-b last:border-0 last:pb-0">
                      <div className={`w-2 h-2 rounded-full mt-2 ${getRiskSeverityColor(item.severity)}`}></div>
                      <div className="flex-1">
                        <h4 className="font-medium">{item.title}</h4>
                        <p className="text-sm text-muted-foreground">{item.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Latest Scan Results */}
        {scanResults && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <RefreshCw size={16} />
                Latest Scan Results
              </CardTitle>
              <CardDescription>
                Latest security analysis from the MCP server
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {scanResults.success ? (
                  <>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-green-600">
                        <CheckCircle size={16} />
                        <span className="font-medium">{scanResults.message || 'Scan completed successfully'}</span>
                      </div>
                      {scanResults.timestamp && (
                        <span className="text-xs text-muted-foreground">
                          {new Date(scanResults.timestamp).toLocaleString()}
                        </span>
                      )}
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      <div className="p-4 bg-blue-50 rounded-lg">
                        <p className="text-sm font-medium text-blue-800">File Analyzed</p>
                        <p className="text-xs text-blue-600 mt-1 truncate">{scanResults.file_path}</p>
                      </div>
                      <div className="p-4 bg-red-50 rounded-lg">
                        <p className="text-sm font-medium text-red-800">Critical</p>
                        <p className="text-2xl font-bold text-red-600">
                          {scanResults.risks?.filter((r: any) => r.severity === 'critical').length || 0}
                        </p>
                      </div>
                      <div className="p-4 bg-yellow-50 rounded-lg">
                        <p className="text-sm font-medium text-yellow-800">Medium</p>
                        <p className="text-2xl font-bold text-yellow-600">
                          {scanResults.risks?.filter((r: any) => r.severity === 'medium').length || 0}
                        </p>
                      </div>
                      <div className="p-4 bg-green-50 rounded-lg">
                        <p className="text-sm font-medium text-green-800">Total Risks</p>
                        <p className="text-2xl font-bold text-green-600">{scanResults.risks_count || 0}</p>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      {/* Left column - Security Constraints and Risks */}
                      <div className="space-y-6">
                        {scanResults.constraints && scanResults.constraints.length > 0 && (
                          <div>
                            <h4 className="font-medium mb-2">Security Constraints:</h4>
                            <ul className="space-y-2">
                              {scanResults.constraints.map((constraint: any, index: number) => (
                                <li key={index} className="text-sm p-2 bg-muted rounded">
                                  {constraint.description}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                        {scanResults.risks && scanResults.risks.length > 0 && (
                          <div>
                            <h4 className="font-medium mb-2">Security Risks:</h4>
                            <ul className="space-y-2">
                              {scanResults.risks.map((risk: any, index: number) => (
                                <li key={index} className="text-sm p-2 bg-red-50 rounded border border-red-200">
                                  <span className={`inline-block px-2 py-1 text-xs rounded-full mr-2 ${
                                    risk.severity === 'critical' ? 'bg-red-100 text-red-800' :
                                    risk.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                                    'bg-green-100 text-green-800'
                                  }`}>
                                    {risk.severity}
                                  </span>
                                  {risk.description}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                      
                      {/* Right column - Security Recommendations */}
                      {scanResults.hardened_code && scanResults.hardened_code.length > 0 && (
                        <div className="h-full flex flex-col">
                          <h4 className="font-medium mb-2">Security Recommendations:</h4>
                          <div className="bg-gray-900 text-green-400 p-3 border rounded-md font-mono text-xs overflow-y-auto" style={{ height: '400px' }}>
                            <pre className="whitespace-pre-wrap">{scanResults.hardened_code.join('\n')}</pre>
                          </div>
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="flex items-center gap-2 text-red-600">
                    <AlertTriangle size={16} />
                    <span>Scan failed: {scanResults.error}</span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Scan History */}
        {scanHistory.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <RefreshCw size={16} />
                Scan History
              </CardTitle>
              <CardDescription>
                Previous security scans and their results
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {scanHistory.map((scan, index) => (
                  <div 
                    key={index} 
                    className="p-4 border rounded-lg hover:shadow-md transition-shadow cursor-pointer"
                    onClick={() => handleScanClick(scan)}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <p className="font-medium text-sm truncate">
                          {scan.file_path ? scan.file_path.split('/').pop() : 'Unknown file'}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                          {scan.timestamp ? new Date(scan.timestamp).toLocaleString() : 'No timestamp'}
                        </p>
                      </div>
                      <span className={`px-2 py-1 text-xs rounded-full ml-2 ${
                        scan.success ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                      }`}>
                        {scan.success ? 'Success' : 'Failed'}
                      </span>
                    </div>
                    
                    <div className="flex gap-2 mt-3">
                      {scan.risks && scan.risks.filter((r: any) => r.severity === 'critical').length > 0 && (
                        <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-800">
                          {scan.risks.filter((r: any) => r.severity === 'critical').length} Critical
                        </span>
                      )}
                      {scan.risks && scan.risks.filter((r: any) => r.severity === 'medium').length > 0 && (
                        <span className="px-2 py-1 text-xs rounded-full bg-yellow-100 text-yellow-800">
                          {scan.risks.filter((r: any) => r.severity === 'medium').length} Medium
                        </span>
                      )}
                    </div>
                    
                    <p className="text-xs text-muted-foreground mt-2">
                      {scan.message || 'Scan completed'}
                    </p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Selected Scan Details Modal */}
        {selectedScan && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-bold">Scan Details</h2>
                  <button
                    onClick={closeSelectedScan}
                    className="text-gray-500 hover:text-gray-700 text-2xl"
                  >
                    ×
                  </button>
                </div>
                
                <div className="space-y-4">
                  {/* Scan Header */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {selectedScan.success ? (
                        <CheckCircle size={16} className="text-green-600" />
                      ) : (
                        <AlertTriangle size={16} className="text-red-600" />
                      )}
                      <span className="font-medium">
                        {selectedScan.success ? 'Scan completed successfully' : 'Scan failed'}
                      </span>
                    </div>
                    {selectedScan.timestamp && (
                      <span className="text-sm text-muted-foreground">
                        {new Date(selectedScan.timestamp).toLocaleString()}
                      </span>
                    )}
                  </div>

                  {/* File Path */}
                  {selectedScan.file_path && (
                    <div className="p-3 bg-gray-50 rounded">
                      <p className="text-sm font-medium">File Analyzed:</p>
                      <p className="text-sm text-muted-foreground">{selectedScan.file_path}</p>
                    </div>
                  )}

                  {/* Risk Summary */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div className="p-4 bg-red-50 rounded-lg">
                      <p className="text-sm font-medium text-red-800">Critical</p>
                      <p className="text-2xl font-bold text-red-600">
                        {selectedScan.risks?.filter((r: any) => r.severity === 'critical').length || 0}
                      </p>
                    </div>
                    <div className="p-4 bg-yellow-50 rounded-lg">
                      <p className="text-sm font-medium text-yellow-800">Medium</p>
                      <p className="text-2xl font-bold text-yellow-600">
                        {selectedScan.risks?.filter((r: any) => r.severity === 'medium').length || 0}
                      </p>
                    </div>
                    <div className="p-4 bg-green-50 rounded-lg">
                      <p className="text-sm font-medium text-green-800">Suggestions</p>
                      <p className="text-2xl font-bold text-green-600">{selectedScan.constraints_count || 0}</p>
                    </div>
                    <div className="p-4 bg-blue-50 rounded-lg">
                      <p className="text-sm font-medium text-blue-800">Total Risks</p>
                      <p className="text-2xl font-bold text-blue-600">{selectedScan.risks_count || 0}</p>
                    </div>
                  </div>

                  {/* Detailed Results */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Left column - Security Constraints and Risks */}
                    <div className="space-y-6">
                      {selectedScan.constraints && selectedScan.constraints.length > 0 && (
                        <div>
                          <h4 className="font-medium mb-2">Security Constraints:</h4>
                          <ul className="space-y-2">
                            {selectedScan.constraints.map((constraint: any, index: number) => (
                              <li key={index} className="text-sm p-2 bg-muted rounded">
                                {constraint.description}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {selectedScan.risks && selectedScan.risks.length > 0 && (
                        <div>
                          <h4 className="font-medium mb-2">Security Risks:</h4>
                          <ul className="space-y-2">
                            {selectedScan.risks.map((risk: any, index: number) => (
                              <li key={index} className="text-sm p-2 bg-red-50 rounded border border-red-200">
                                <span className={`inline-block px-2 py-1 text-xs rounded-full mr-2 ${
                                  risk.severity === 'critical' ? 'bg-red-100 text-red-800' :
                                  risk.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                                  'bg-green-100 text-green-800'
                                }`}>
                                  {risk.severity}
                                </span>
                                {risk.description}
                                {risk.impact && (
                                  <p className="text-xs text-muted-foreground mt-1">Impact: {risk.impact}</p>
                                )}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                    
                    {/* Right column - Security Recommendations */}
                    {selectedScan.hardened_code && selectedScan.hardened_code.length > 0 && (
                      <div className="h-full flex flex-col">
                        <h4 className="font-medium mb-2">Security Recommendations:</h4>
                        <div className="bg-gray-900 text-green-400 p-3 border rounded-md font-mono text-xs overflow-y-auto" style={{ height: '400px' }}>
                          <pre className="whitespace-pre-wrap">{selectedScan.hardened_code.join('\n')}</pre>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Error Message */}
                  {selectedScan.error && (
                    <div className="p-3 bg-red-50 border border-red-200 rounded">
                      <p className="text-sm font-medium text-red-800">Error:</p>
                      <p className="text-sm text-red-600">{selectedScan.error}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  );
};

export default Dashboard; 