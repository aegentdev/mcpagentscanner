import { useState, useEffect, useRef } from 'react';
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
  Menu,
  X,
  ChevronDown,
  Folder
} from 'lucide-react';

interface AppLayoutProps {
  children: React.ReactNode;
  latestScanTime?: string;
}

const AppLayout: React.FC<AppLayoutProps> = ({ children, latestScanTime }) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [isProjectsDropdownOpen, setIsProjectsDropdownOpen] = useState(false);
  const [selectedProject, setSelectedProject] = useState('Quantum Traders');
  const location = useLocation();
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsProjectsDropdownOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  interface NavigationItem {
    name: string;
    href: string;
    icon: any;
    tag?: string;
  }

  const navigation = [
    {
      section: "Overview Analysis",
      items: [
        { name: "Dashboard", href: "/", icon: Activity },
        { name: "System Schema", href: "/system-schema", icon: BarChart3 },
        { name: "Vulnerability Scan", href: "/vulnerability-scan", icon: Search },
        { name: "Attack Monitoring", href: "/attack-monitoring", icon: Eye },
        { name: "Threat Intelligence", href: "/threat-intelligence", icon: Triangle },
      ] as NavigationItem[]
    },
    {
      section: "Attack Vectors",
      items: [
        { name: "Data Poisoning", href: "/data-poisoning", icon: Shield, tag: "Medium" },
        { name: "Jailbreaks", href: "/jailbreaks", icon: Shield, tag: "Critical" },
      ] as NavigationItem[]
    },
    {
      section: "Security & Monitoring",
      items: [
        { name: "Hardening Tools", href: "/hardening-tools", icon: Wrench },
        { name: "Prompt Hardening", href: "/prompt-hardening", icon: Shield },
        { name: "Risk Reports", href: "/risk-reports", icon: FileText },
        { name: "System Monitor", href: "/system-monitor", icon: BarChart3 },
      ] as NavigationItem[]
    }
  ];

  const projects = [
    { id: 'quantum-traders', name: 'Quantum Traders', description: 'Multi-agent quantum trading system' },
    { id: 'bio-research', name: 'Bio Research Lab', description: 'AI agents for drug discovery' },
    { id: 'space-explorer', name: 'Space Explorer', description: 'Autonomous space mission planning' },
    { id: 'climate-predictor', name: 'Climate Predictor', description: 'Environmental modeling agents' },
    { id: 'cyber-sentinel', name: 'Cyber Sentinel', description: 'Advanced threat detection network' },
    { id: 'creative-studio', name: 'Creative Studio', description: 'AI-powered content generation' },
    { id: 'smart-city', name: 'Smart City Hub', description: 'Urban infrastructure management' },
    { id: 'medical-diagnosis', name: 'Medical Diagnosis', description: 'Healthcare diagnostic agents' },
    { id: 'financial-advisor', name: 'Financial Advisor', description: 'Investment portfolio optimization' },
    { id: 'game-developer', name: 'Game Developer', description: 'Procedural game world generation' }
  ];

  return (
    <div className="min-h-screen">
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
            <nav className="flex-1 p-4 space-y-6 overflow-y-auto">
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
                <div className="flex items-center space-x-2">
                  <div className="w-4 h-4 bg-green-500 rounded-full"></div>
                  <div>
                    <p className="text-sm font-medium">Latest Scan</p>
                    <p className="text-xs text-muted-foreground">
                      {latestScanTime ? new Date(latestScanTime).toLocaleString() : 'No scans yet'}
                    </p>
                  </div>
                </div>
              </div>
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center">
                    <span className="text-primary-foreground text-sm font-medium">U</span>
                  </div>
                  <div className="hidden md:block">
                    <p className="text-sm font-medium">Current User</p>
                    <p className="text-xs text-muted-foreground">user@example.com</p>
                  </div>
                </div>
                
                {/* Projects Dropdown */}
                <div className="relative" ref={dropdownRef}>
                  <button
                    onClick={() => setIsProjectsDropdownOpen(!isProjectsDropdownOpen)}
                    className="flex items-center space-x-2 px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground hover:bg-accent rounded-md transition-colors"
                  >
                    <Folder size={16} />
                    <span className="hidden md:block">{selectedProject}</span>
                    <ChevronDown size={14} className={`transition-transform ${isProjectsDropdownOpen ? 'rotate-180' : ''}`} />
                  </button>
                  
                  {isProjectsDropdownOpen && (
                    <div className="absolute right-0 mt-2 w-64 bg-card border border-border rounded-md shadow-lg z-50">
                      <div className="p-2">
                        <div className="px-3 py-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                          Projects
                        </div>
                        {projects.map((project) => (
                          <button
                            key={project.id}
                            onClick={() => {
                              setSelectedProject(project.name);
                              setIsProjectsDropdownOpen(false);
                            }}
                            className={`w-full text-left px-3 py-2 text-sm rounded-md transition-colors ${
                              selectedProject === project.name
                                ? 'bg-accent text-accent-foreground'
                                : 'text-foreground hover:bg-accent hover:text-accent-foreground'
                            }`}
                          >
                            <div className="font-medium">{project.name}</div>
                            <div className="text-xs text-muted-foreground">{project.description}</div>
                          </button>
                        ))}
                        <div className="border-t border-border mt-2 pt-2">
                          <button className="w-full text-left px-3 py-2 text-sm text-blue-600 hover:bg-accent rounded-md transition-colors">
                            + Create New Project
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
                
                <button
                  className="px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground hover:bg-accent rounded-md transition-colors"
                >
                  Sign Out
                </button>
              </div>
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