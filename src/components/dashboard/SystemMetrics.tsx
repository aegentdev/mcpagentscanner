
import { Card, CardContent } from '@/components/ui/card';

interface SystemOverview {
  totalScans: number;
  totalCritical: number;
  totalMedium: number;
  highRiskCount: number;
}

interface SystemMetricsProps {
  data: SystemOverview;
}

const SystemMetrics: React.FC<SystemMetricsProps> = ({ data }) => {
  const metrics = [
    {
      label: 'Total Scans',
      value: data.totalScans,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
      borderColor: 'border-blue-200'
    },
    {
      label: 'Number Critical Risks',
      value: data.totalCritical,
      color: 'text-red-600',
      bgColor: 'bg-red-50',
      borderColor: 'border-red-200'
    },
    {
      label: 'Number Medium Risks',
      value: data.totalMedium,
      color: 'text-yellow-600',
      bgColor: 'bg-yellow-50',
      borderColor: 'border-yellow-200'
    },
    {
      label: 'High Risk',
      value: data.highRiskCount,
      color: 'text-orange-600',
      bgColor: 'bg-orange-50',
      borderColor: 'border-orange-200'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {metrics.map((metric, index) => (
        <Card key={index} className={`${metric.bgColor} ${metric.borderColor} border-2`}>
          <CardContent className="pt-8 pb-8 px-8">
            <div className="text-center space-y-4">
              <p className="text-sm font-medium text-muted-foreground leading-tight">
                {metric.label}
              </p>
              <p className={`text-4xl font-bold ${metric.color} leading-none`}>
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