import React from 'react';
import { Card, CardContent } from '@/components/ui/card';

interface SystemOverview {
  compromised: number;
  avgRiskScore: number;
  connectivity: number;
  highRiskCount: number;
}

interface SystemMetricsProps {
  data: SystemOverview;
}

const SystemMetrics: React.FC<SystemMetricsProps> = ({ data }) => {
  const metrics = [
    {
      label: 'Compromised',
      value: data.compromised,
      color: 'text-green-600',
      bgColor: 'bg-green-50',
      borderColor: 'border-green-200'
    },
    {
      label: 'Avg Risk Score',
      value: data.avgRiskScore,
      color: 'text-orange-600',
      bgColor: 'bg-orange-50',
      borderColor: 'border-orange-200'
    },
    {
      label: 'Connectivity',
      value: `${data.connectivity}%`,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
      borderColor: 'border-blue-200'
    },
    {
      label: 'High Risk',
      value: data.highRiskCount,
      color: 'text-red-600',
      bgColor: 'bg-red-50',
      borderColor: 'border-red-200'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {metrics.map((metric, index) => (
        <Card key={index} className={`${metric.bgColor} ${metric.borderColor} border-2`}>
          <CardContent className="p-6">
            <div className="text-center">
              <p className="text-sm font-medium text-muted-foreground mb-2">
                {metric.label}
              </p>
              <p className={`text-3xl font-bold ${metric.color}`}>
                {metric.value}
              </p>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
};

export default SystemMetrics; 