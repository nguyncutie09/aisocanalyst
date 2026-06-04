import React from 'react';
import MitreHeatmap from '../components/MitreHeatmap';

export default function MitrePage() {
    return (
        <div>
            <h1 className="page-title">MITRE ATT&CK Coverage</h1>
            <p style={{ color: 'var(--text-muted)', marginBottom: 24 }}>
                Detected tactics and techniques mapped to the MITRE ATT&CK framework
            </p>

            <div className="panel">
                <div className="panel-header">Tactic Coverage Heatmap</div>
                <div className="panel-body">
                    <MitreHeatmap />
                </div>
            </div>

            <div className="panel" style={{ marginTop: 24 }}>
                <div className="panel-header">MITRE ATT&CK Legend</div>
                <div className="panel-body">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Tactic</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {[
                                ['TA0001', 'Initial Access', 'Getting into your network'],
                                ['TA0002', 'Execution', 'Running malicious code'],
                                ['TA0003', 'Persistence', 'Maintaining foothold'],
                                ['TA0004', 'Privilege Escalation', 'Gaining higher permissions'],
                                ['TA0005', 'Defense Evasion', 'Avoiding detection'],
                                ['TA0006', 'Credential Access', 'Stealing credentials'],
                                ['TA0007', 'Discovery', 'Figuring out environment'],
                                ['TA0008', 'Lateral Movement', 'Moving through environment'],
                                ['TA0009', 'Collection', 'Gathering data'],
                                ['TA0011', 'Command and Control', 'Communicating with compromised systems'],
                            ].map(([id, name, desc]) => (
                                <tr key={id}>
                                    <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{id}</td>
                                    <td>{name}</td>
                                    <td style={{ color: 'var(--text-muted)' }}>{desc}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
