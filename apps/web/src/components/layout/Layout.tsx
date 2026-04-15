import { Link, useLocation } from 'react-router-dom';
import { Shield, Home, PlusCircle, Settings, Activity } from 'lucide-react';
import clsx from 'clsx';
import type { ReactNode } from 'react';

const navigation = [
  { name: 'Dashboard', href: '/', icon: Home },
  { name: 'New Scan', href: '/scans/new', icon: PlusCircle },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export function Layout({ children }: { children: ReactNode }) {
  const location = useLocation();

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className="w-64 bg-brand-900 text-white flex flex-col">
        <div className="p-6 flex items-center gap-3">
          <Shield className="w-8 h-8 text-brand-500" />
          <div>
            <h1 className="text-lg font-bold">SecureScope</h1>
            <p className="text-xs text-gray-400">VAPT Platform</p>
          </div>
        </div>

        <nav className="flex-1 px-4 space-y-1">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href;
            return (
              <Link
                key={item.name}
                to={item.href}
                className={clsx(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-brand-700 text-white'
                    : 'text-gray-300 hover:bg-brand-700/50 hover:text-white',
                )}
              >
                <item.icon className="w-5 h-5" />
                {item.name}
              </Link>
            );
          })}
        </nav>

        <div className="p-4 border-t border-brand-700">
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <Activity className="w-4 h-4" />
            <span>System Healthy</span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <div className="max-w-7xl mx-auto px-6 py-8">
          {children}
        </div>
      </main>
    </div>
  );
}
