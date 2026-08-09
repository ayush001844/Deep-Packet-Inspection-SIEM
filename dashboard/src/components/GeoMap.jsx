import React, { useMemo } from 'react';
import { ComposableMap, Geographies, Geography, Marker, Line, Annotation } from 'react-simple-maps';

const geoUrl = '/features.json';

export default function GeoMap({ nodes = [], links = [], alerts = [] }) {
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

  // Extract alerts with geo data for drawing attack arcs
  const attackArcs = useMemo(() => {
    return alerts.filter(a => a.src_geo?.lat && a.dst_geo?.lat).map(alert => ({
      ...alert,
      sourceCoordinates: [alert.src_geo.lon, alert.src_geo.lat],
      targetCoordinates: [alert.dst_geo.lon, alert.dst_geo.lat],
    }));
  }, [alerts]);

  return (
    <div style={{ width: '100%', height: '100%', backgroundColor: '#0a0a0b', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden', position: 'relative' }}>
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

        {/* Draw active connection lines */}
        {geoLinks.map((link, i) => (
          <Line
            key={`link-${i}`}
            from={link.sourceGeo}
            to={link.targetGeo}
            stroke="rgba(59, 130, 246, 0.2)"
            strokeWidth={0.5}
            strokeLinecap="round"
            style={{ default: { outline: 'none' } }}
          />
        ))}

        {/* Draw Live Attack Arcs */}
        {attackArcs.map((arc, i) => (
          <g key={`arc-${i}`}>
            <Line
              from={arc.sourceCoordinates}
              to={arc.targetCoordinates}
              stroke="#ef4444"
              strokeWidth={1.5}
              strokeLinecap="round"
              className="attack-arc"
              style={{
                default: { outline: 'none' },
              }}
            />
            {/* Annotation Label for the Attack */}
            <Annotation
              subject={arc.sourceCoordinates}
              dx={-30}
              dy={-30}
              connectorProps={{
                stroke: "#ef4444",
                strokeWidth: 1,
                strokeLinecap: "round"
              }}
            >
              <text x="-8" textAnchor="end" alignmentBaseline="middle" fill="#ef4444" fontSize="10" fontWeight="bold">
                {arc.src_geo.country}
              </text>
              <text x="-8" y="12" textAnchor="end" alignmentBaseline="middle" fill="#fca5a5" fontSize="8">
                {arc.title || "Attack"}
              </text>
            </Annotation>
          </g>
        ))}

        {/* Draw markers for each IP with coordinates */}
        {geoNodes.map((node, i) => (
          <Marker key={`marker-${i}`} coordinates={[node.geo.lon, node.geo.lat]}>
            <circle
              r={2}
              fill="#3b82f6"
              stroke="#0a0a0b"
              strokeWidth={1}
            />
          </Marker>
        ))}

        {/* Draw markers for Attack Sources and Destinations */}
        {attackArcs.map((arc, i) => (
          <React.Fragment key={`attack-markers-${i}`}>
            <Marker coordinates={arc.sourceCoordinates}>
              <circle r={4} fill="#ef4444" />
              <circle r={8} fill="none" stroke="#ef4444" strokeWidth={1} className="pulse-animation" />
            </Marker>
            <Marker coordinates={arc.targetCoordinates}>
              <circle r={4} fill="#f59e0b" />
              <circle r={8} fill="none" stroke="#f59e0b" strokeWidth={1} className="pulse-animation" />
            </Marker>
          </React.Fragment>
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
        @keyframes dash {
          to {
            stroke-dashoffset: 0;
          }
        }
        .attack-arc {
          stroke-dasharray: 5, 5;
          stroke-dashoffset: 20;
          animation: dash 1s linear infinite;
        }
      `}</style>
    </div>
  );
}
