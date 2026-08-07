import React, { useMemo } from 'react';
import { ComposableMap, Geographies, Geography, Marker, Line } from 'react-simple-maps';

const geoUrl = '/features.json';

export default function GeoMap({ nodes, links }) {
  // We need to filter nodes that actually have valid geo coordinates
  const geoNodes = useMemo(() => {
    return nodes.filter(n => n.geo && n.geo.lat && n.geo.lon);
  }, [nodes]);

  const geoLinks = useMemo(() => {
    return links.map(link => {
      const sourceNode = typeof link.source === 'object' ? link.source : nodes.find(n => n.id === link.source);
      const targetNode = typeof link.target === 'object' ? link.target : nodes.find(n => n.id === link.target);
      
      if (sourceNode?.geo?.lat && targetNode?.geo?.lat) {
        return {
          ...link,
          sourceGeo: [sourceNode.geo.lon, sourceNode.geo.lat],
          targetGeo: [targetNode.geo.lon, targetNode.geo.lat],
        };
      }
      return null;
    }).filter(Boolean);
  }, [links, nodes]);

  return (
    <div style={{ width: '100%', height: '100%', backgroundColor: '#0a0a0b', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
      <ComposableMap
        projection="geoMercator"
        projectionConfig={{
          scale: 130,
        }}
        style={{ width: '100%', height: '100%' }}
      >
        <Geographies geography={geoUrl}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill="#1f2937"
                stroke="#374151"
                strokeWidth={0.5}
                style={{
                  default: { outline: 'none' },
                  hover: { fill: '#374151', outline: 'none' },
                  pressed: { outline: 'none' },
                }}
              />
            ))
          }
        </Geographies>

        {/* Draw connections (lines) between nodes */}
        {geoLinks.map((link, i) => (
          <Line
            key={`line-${i}`}
            from={link.sourceGeo}
            to={link.targetGeo}
            stroke={link.is_suspicious ? "#ef4444" : "rgba(59, 130, 246, 0.4)"}
            strokeWidth={link.is_suspicious ? 1.5 : 0.5}
            strokeLinecap="round"
            style={{
              default: { outline: 'none' },
            }}
          />
        ))}

        {/* Draw markers for each IP with coordinates */}
        {geoNodes.map((node, i) => (
          <Marker key={`marker-${i}`} coordinates={[node.geo.lon, node.geo.lat]}>
            <circle
              r={node.group === 1 ? 4 : 2}
              fill={node.group === 1 ? "#ef4444" : "#3b82f6"}
              stroke="#0a0a0b"
              strokeWidth={1}
            />
            {node.group === 1 && (
              <circle
                r={8}
                fill="none"
                stroke="#ef4444"
                strokeWidth={1}
                className="pulse-animation"
              />
            )}
          </Marker>
        ))}
      </ComposableMap>
      <style>{`
        @keyframes pulse {
          0% { transform: scale(0.5); opacity: 1; }
          100% { transform: scale(2); opacity: 0; }
        }
        .pulse-animation {
          animation: pulse 2s infinite;
          transform-origin: center;
        }
      `}</style>
    </div>
  );
}
