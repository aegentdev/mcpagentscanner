import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Activity, 
  Shield, 
  Search, 
  Eye, 
  Triangle, 
  Wrench, 
  FileText, 
  BarChart3,
  Moon,
  Sun,
  Menu,
  X
} from 'lucide-react';

interface AppLayoutProps {
  children: React.ReactNode;
}

const AppLayout: React.FC<AppLayoutProps> = ({ children }) => {
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const location = useLocation();

  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
    document.documentElement.classList.toggle('dark');
  };

  const navigation = [
    {
      section: "Overview Analysis",
      items: [
        { name: "Dashboard", href: "/", icon: Activity },
        { name: "System Schema", href: "/system-schema", icon: BarChart3 },
        { name: "Vulnerability Scan", href: "/vulnerability-scan", icon: Search },
        { name: "Attack Monitoring", href: "/attack-monitoring", icon: Eye },
        { name: "Threat Intelligence", href: "/threat-intelligence", icon: Triangle },
      ]
    },
    {
      section: "Attack Vectors",
      items: [
        { name: "Data Poisoning", href: "/data-poisoning", icon: Shield, tag: "Medium" },
        { name: "Jailbreaks", href: "/jailbreaks", icon: Shield, tag: "Critical" },
      ]
    },
    {
      section: "Security & Monitoring",
      items: [
        { name: "Hardening Tools", href: "/hardening-tools", icon: Wrench },
        { name: "Prompt Hardening", href: "/prompt-hardening", icon: Shield },
        { name: "Risk Reports", href: "/risk-reports", icon: FileText },
        { name: "System Monitor", href: "/system-monitor", icon: BarChart3 },
      ]
    }
  ];

  return (
    <div className={`min-h-screen ${isDarkMode ? 'dark' : ''}`}>
      <div className="flex h-screen bg-background">
        {/* Sidebar */}
        <div className={`${isSidebarOpen ? 'w-64' : 'w-16'} bg-sidebar border-r border-sidebar-border transition-all duration-300 ease-in-out`}>
          <div className="flex flex-col h-full">
            {/* Header */}
            <div className="p-4 border-b border-sidebar-border">
              <div className="flex items-center justify-between">
                <div className={`${isSidebarOpen ? 'block' : 'hidden'}`}>
                  <h1 className="text-lg font-bold text-sidebar-foreground">aegent/dev</h1>
                  <p className="text-sm text-sidebar-foreground">Agentic Security Scanner</p>
                  <p className="text-xs text-muted-foreground mt-2">
                    This is a proof of concept of our multi agent security scanner. 
                    We love ideas and recommendations of what you'd like to see in such a tool! 
                    <a href="#" className="text-blue-600 underline"> Click here to contact us!</a>
                  </p>
                </div>
                <button
                  onClick={() => setIsSidebarOpen(!isSidebarOpen)}
                  className="p-2 rounded-md hover:bg-sidebar-accent"
                >
                  {isSidebarOpen ? <X size={16} /> : <Menu size={16} />}
                </button>
              </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 p-4 space-y-6">
              {navigation.map((section) => (
                <div key={section.section}>
                  <h3 className={`text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 ${!isSidebarOpen && 'hidden'}`}>
                    {section.section}
                  </h3>
                  <ul className="space-y-1">
                    {section.items.map((item) => {
                      const Icon = item.icon;
                      const isActive = location.pathname === item.href;
                      return (
                        <li key={item.name}>
                          <Link
                            to={item.href}
                            className={`flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                              isActive
                                ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                                : 'text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground'
                            }`}
                          >
                            <Icon size={16} className="mr-3" />
                            {isSidebarOpen && (
                              <>
                                <span className="flex-1">{item.name}</span>
                                {item.tag && (
                                  <span className={`px-2 py-1 text-xs rounded-full ${
                                    item.tag === 'Critical' 
                                      ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                                      : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                                  }`}>
                                    {item.tag}
                                  </span>
                                )}
                              </>
                            )}
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </nav>

            {/* Footer */}
            <div className="p-4 border-t border-sidebar-border">
              <div className={`${isSidebarOpen ? 'block' : 'hidden'}`}>
                <p className="text-xs text-muted-foreground">
                  Click here to check out our research and blogs!
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Main content */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Top bar */}
          <header className="bg-card border-b border-border px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <h1 className="text-2xl font-bold">Dashboard</h1>
                <p className="text-muted-foreground">Overview of your multi-agent system security status</p>
              </div>
              <button
                onClick={toggleDarkMode}
                className="p-2 rounded-md hover:bg-accent"
              >
                {isDarkMode ? <Sun size={20} /> : <Moon size={20} />}
              </button>
            </div>
          </header>

          {/* Page content */}
          <main className="flex-1 overflow-auto">
            {children}
          </main>
        </div>
      </div>
    </div>
  );
};

export default AppLayout; 