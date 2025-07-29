import { useState, useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Activity, 
  Search, 
  Eye, 
  Triangle, 
  Wrench, 
  FileText, 
  ChevronDown,
  Folder,
  Link as LinkIcon,
  Database,
  Unlock,
  CheckCircle
} from 'lucide-react';

interface AppLayoutProps {
  children: React.ReactNode;
  latestScanTime?: string;
}

const AppLayout: React.FC<AppLayoutProps> = ({ children, latestScanTime }) => {

  const [isProjectsDropdownOpen, setIsProjectsDropdownOpen] = useState(false);
  const [selectedProject, setSelectedProject] = useState('Multi Agent System');
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
        { name: "System Schema", href: "/system-schema", icon: LinkIcon },
        { name: "Vulnerability Scan", href: "/vulnerability-scan", icon: Search },
        { name: "Attack Monitoring", href: "/attack-monitoring", icon: Eye },
        { name: "Threat Intelligence", href: "/threat-intelligence", icon: Triangle },
      ] as NavigationItem[]
    },
    {
      section: "Attack Vectors",
      items: [
        { name: "Data Poisoning", href: "/data-poisoning", icon: Database, tag: "Medium" },
        { name: "Jailbreaks", href: "/jailbreaks", icon: Unlock, tag: "Critical" },
      ] as NavigationItem[]
    },
    {
      section: "Security & Monitoring",
      items: [
        { name: "Hardening Tools", href: "/hardening-tools", icon: Wrench },
        { name: "Prompt Hardening", href: "/prompt-hardening", icon: CheckCircle },
        { name: "Risk Reports", href: "/risk-reports", icon: FileText },
        { name: "System Monitor", href: "/system-monitor", icon: Activity },
      ] as NavigationItem[]
    }
  ];

  const projects = [
    { id: 'multi-agent-system', name: 'Multi Agent System', description: 'Comprehensive multi-agent security scanner' }
  ];

  return (
    <div className="min-h-screen">
      <div className="flex h-screen bg-background">
        {/* Sidebar */}
        <div className="w-64 bg-sidebar border-r border-sidebar-border">
          <div className="flex flex-col h-full">
            {/* Header */}
            <div className="p-4 border-b border-sidebar-border">
              <div>
                <h1 className="text-lg font-bold text-sidebar-foreground">aegent/dev</h1>
                <p className="text-xs text-sidebar-foreground">Agentic Security Scanner</p>
                                  <p className="text-xs text-muted-foreground mt-2">
                    This is a proof of concept of our multi agent security scanner. 
                    We love ideas and recommendations of what you'd like to see in such a tool! 
                    <a href="https://www.aegentdev.com/contact" target="_blank" rel="noopener noreferrer" className="text-blue-600 underline"> Click here to contact us!</a>
                  </p>
              </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 p-4 space-y-6 overflow-y-auto">
              {navigation.map((section) => (
                <div key={section.section}>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
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
                                  : 'text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground'
                              }`}
                            >
                            <Icon size={18} className="mr-3" />
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
              <div>
                <p className="text-xs text-muted-foreground">
                  <a href="https://www.aegentdev.com/blog" target="_blank" rel="noopener noreferrer" className="text-blue-600 underline hover:text-blue-800">
                    Click here to check out our research and blogs!
                  </a>
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
                <a 
                  href="https://www.mvp.aegentdev.com/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="flex items-center space-x-1 px-2 py-1 text-xs text-gray-600 hover:text-gray-800 border border-gray-300 rounded hover:bg-gray-50 transition-colors"
                >
                  <span>View our POC here</span>
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                </a>
                <a 
                  href="https://www.aegentdev.com/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="flex items-center space-x-1 px-2 py-1 text-xs text-gray-600 hover:text-gray-800 border border-gray-300 rounded hover:bg-gray-50 transition-colors"
                >
                  <span>Website</span>
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                </a>
              </div>
              <div className="flex items-center space-x-4">
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
                            + Ability to add more projects coming soon
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
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