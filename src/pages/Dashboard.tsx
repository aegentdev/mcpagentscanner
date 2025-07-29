import React, { useState, useEffect } from 'react';
import AppLayout from '@/components/layout/AppLayout';
import SystemMetrics from '@/components/dashboard/SystemMetrics';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { RefreshCw, AlertTriangle, CheckCircle, Info } from 'lucide-react';

interface SystemOverview {
  compromised: number;
  avgRiskScore: number;
  connectivity: number;
  highRiskCount: number;
}

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
}

const Dashboard = () => {
  const [systemOverview] = useState<SystemOverview>({
    compromised: 0,
    avgRiskScore: 6.7,
    connectivity: 33,
    highRiskCount: 2
  });

  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);

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

  const activityItems = [
    {
      type: 'warning',
      title: 'Unusual prompt pattern detected',
      description: 'LLM Agent received potentially malicious prompt pattern',
      time: '10 minutes ago'
    },
    {
      type: 'info',
      title: 'System scan completed',
      description: 'Full system vulnerability scan completed successfully',
      time: '1 hour ago'
    },
    {
      type: 'error',
      title: 'Prompt injection attempt',
      description: 'Blocked attempt to inject malicious prompt into LLM Agent',
      time: '3 hours ago'
    },
    {
      type: 'success',
      title: 'Guardrails updated',
      description: 'System guardrails updated with latest security patterns',
      time: '1 day ago'
    }
  ];

  const riskItems = [
    {
      severity: 'high',
      title: 'LLM Agent Prompt Vulnerability',
      description: 'High autonomy settings create risk of prompt manipulation'
    },
    {
      severity: 'medium',
      title: 'Executor Tool Access',
      description: 'Executor has elevated access to system tools'
    },
    {
      severity: 'low',
      title: 'Planner Memory Usage',
      description: 'Memory allocation for Planner agent may lead to information leakage'
    }
  ];

  const getActivityTypeColor = (type: string) => {
    switch (type) {
      case 'warning': return 'bg-yellow-500';
      case 'error': return 'bg-red-500';
      case 'success': return 'bg-green-500';
      default: return 'bg-blue-500';
    }
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'warning': return <AlertTriangle size={16} />;
      case 'error': return <AlertTriangle size={16} />;
      case 'success': return <CheckCircle size={16} />;
      default: return <Info size={16} />;
    }
  };

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
    <AppLayout>
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
        
        <SystemMetrics data={systemOverview} />
        
        <Tabs defaultValue="recent-activity">
          <TabsList className="grid w-full md:w-[400px] grid-cols-2">
            <TabsTrigger value="recent-activity">Recent Activity</TabsTrigger>
            <TabsTrigger value="risk-summary">Risk Summary</TabsTrigger>
          </TabsList>
          
          <TabsContent value="recent-activity" className="mt-4 space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Recent Activity</CardTitle>
                <CardDescription>
                  Latest security events and system changes
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {activityItems.map((item, index) => (
                    <div key={index} className="flex items-start gap-4 pb-4 border-b last:border-0 last:pb-0">
                      <div className={`w-2 h-2 mt-2 rounded-full ${getActivityTypeColor(item.type)}`} />
                      <div className="flex-1">
                        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-1">
                          <p className="font-medium">{item.title}</p>
                          <span className="text-xs text-muted-foreground">{item.time}</span>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">{item.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
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
                      <div className={`w-2 h-2 mt-2 rounded-full ${getRiskSeverityColor(item.severity)}`} />
                      <div className="flex-1">
                        <p className="font-medium">{item.title}</p>
                        <p className="text-sm text-muted-foreground mt-1">{item.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* MCP Scanner Results */}
        {scanResults && (
          <Card>
            <CardHeader>
              <CardTitle>MCP Scanner Results</CardTitle>
              <CardDescription>
                Latest security analysis from the MCP server
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {scanResults.success ? (
                  <>
                    <div className="flex items-center gap-2 text-green-600">
                      <CheckCircle size={16} />
                      <span className="font-medium">Scan completed successfully</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="p-4 bg-blue-50 rounded-lg">
                        <p className="text-sm font-medium text-blue-800">File Analyzed</p>
                        <p className="text-xs text-blue-600 mt-1">{scanResults.file_path}</p>
                      </div>
                      <div className="p-4 bg-yellow-50 rounded-lg">
                        <p className="text-sm font-medium text-yellow-800">Constraints Found</p>
                        <p className="text-2xl font-bold text-yellow-600">{scanResults.constraints_count}</p>
                      </div>
                      <div className="p-4 bg-red-50 rounded-lg">
                        <p className="text-sm font-medium text-red-800">Risks Identified</p>
                        <p className="text-2xl font-bold text-red-600">{scanResults.risks_count}</p>
                      </div>
                    </div>
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
              <CardTitle>Scan History</CardTitle>
              <CardDescription>
                Previous security scans and their results
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {scanHistory.map((scan, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-muted rounded-lg">
                    <div>
                      <p className="font-medium">{scan.file_path || 'Unknown file'}</p>
                      <p className="text-sm text-muted-foreground">
                        {scan.constraints_count} constraints, {scan.risks_count} risks
                      </p>
                    </div>
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      scan.success ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                    }`}>
                      {scan.success ? 'Success' : 'Failed'}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </AppLayout>
  );
};

export default Dashboard; 