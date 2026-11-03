import { NavLink } from 'react-router-dom';

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

const navSections = [
  {
    title: 'Overview',
    items: [
      { path: '/', label: 'Dashboard', icon: '◉' },
      { path: '/alerts', label: 'Alerts', icon: '⚠' },
      { path: '/health', label: 'System Health', icon: '♥' },
    ],
  },
  {
    title: 'Monitoring',
    items: [
      { path: '/processes', label: 'Processes', icon: '⊞' },
      { path: '/files', label: 'Files', icon: '◧' },
      { path: '/network', label: 'Network', icon: '◎' },
      { path: '/auth', label: 'Auth Events', icon: '◈' },
    ],
  },
  {
    title: 'Detection',
    items: [
      { path: '/rules', label: 'Detection Rules', icon: '⊕' },
      { path: '/ai', label: 'AI Engine', icon: '◆' },
      { path: '/hunt', label: 'Threat Hunting', icon: '⊗' },
    ],
  },
  {
    title: 'Prevention',
    items: [
      { path: '/enforcement', label: 'Enforcement', icon: '⊘' },
      { path: '/audit', label: 'Audit Log', icon: '◪' },
      { path: '/ransomware', label: 'Ransomware', icon: '◬' },
      { path: '/persistence', label: 'Persistence', icon: '◫' },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      { path: '/file-intel', label: 'File Intel', icon: '◩' },
      { path: '/forensics', label: 'Forensics', icon: '◮' },
      { path: '/posture', label: 'Posture', icon: '◭' },
      { path: '/tamper', label: 'Tamper Guard', icon: '◯' },
    ],
  },
  {
    title: 'System',
    items: [
      { path: '/command', label: 'Command Center', icon: '▣' },
      { path: '/settings', label: 'Settings', icon: '⚙' },
      { path: '/about', label: 'About', icon: 'ⓘ' },
    ],
  },
];

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <div className="logo">
          <span className="logo-icon">🛡</span>
          {!collapsed && <span className="logo-text">OS Defender</span>}
        </div>
        <button className="toggle-btn" onClick={onToggle} title={collapsed ? 'Expand' : 'Collapse'}>
          {collapsed ? '▸' : '◂'}
        </button>
      </div>
      <nav className="sidebar-nav">
        {navSections.map((section) => (
          <div key={section.title} className="nav-section">
            {!collapsed && <h3 className="nav-section-title">{section.title}</h3>}
            {section.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                title={collapsed ? item.label : undefined}
              >
                <span className="nav-icon">{item.icon}</span>
                {!collapsed && <span className="nav-label">{item.label}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
    </aside>
  );
}
