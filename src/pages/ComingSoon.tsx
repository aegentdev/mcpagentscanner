
import AppLayout from '@/components/layout/AppLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Clock, Construction } from 'lucide-react';

interface ComingSoonProps {
  title: string;
  description?: string;
}

const ComingSoon: React.FC<ComingSoonProps> = ({ title, description = "This feature is under development and will be available soon." }) => {
  return (
    <AppLayout>
      <div className="min-h-screen flex items-center justify-center p-6">
        <div className="max-w-2xl w-full text-center space-y-6">
          <div className="flex justify-center">
            <div className="p-4 bg-primary/10 rounded-full">
              <Construction size={48} className="text-primary" />
            </div>
          </div>
          
          <div className="space-y-2">
            <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
            <p className="text-muted-foreground text-lg">{description}</p>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-center gap-2">
                <Clock size={20} />
                Coming Soon
              </CardTitle>
              <CardDescription>
                We're working hard to bring you this feature
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-center gap-3 p-3 bg-muted rounded-lg">
                  <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
                  <span className="text-sm">Feature development in progress</span>
                </div>
                <div className="flex items-center justify-center gap-3 p-3 bg-muted rounded-lg">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse"></div>
                  <span className="text-sm">Security testing and validation</span>
                </div>
                <div className="flex items-center justify-center gap-3 p-3 bg-muted rounded-lg">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-sm">Final integration and deployment</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <p className="text-sm text-muted-foreground">
            Check back soon for updates, or contact us for more information about this feature.
          </p>
        </div>
      </div>
    </AppLayout>
  );
};

export default ComingSoon; 