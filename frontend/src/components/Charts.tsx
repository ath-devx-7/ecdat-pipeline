import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Verdict, Wave } from "../api";
import {
  VERDICT_COLOR,
  VERDICT_LABEL,
  VERDICTS,
  WAVE_COLOR,
  WAVE_SHORT,
  WAVES,
} from "../lib/labels";

// Two bar charts, one per vocabulary. Every category is drawn whether or not it
// has members — an empty `no_path` column and an empty `wave_2` column are
// statements, not gaps.

export function VerdictChart({ counts }: { counts: Record<string, number> }) {
  const data = VERDICTS.map((verdict: Verdict) => ({
    key: verdict,
    name: VERDICT_LABEL[verdict],
    count: counts[verdict] ?? 0,
  }));
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
        <XAxis dataKey="name" tick={{ fontSize: 11 }} interval={0} />
        <YAxis allowDecimals={false} tick={{ fontSize: 11 }} width={32} />
        <Tooltip />
        <Bar dataKey="count" isAnimationActive={false}>
          {data.map((entry) => (
            <Cell key={entry.key} fill={VERDICT_COLOR[entry.key]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function WaveChart({ counts }: { counts: Record<string, number> }) {
  const data = WAVES.map((wave: Wave) => ({
    key: wave,
    name: WAVE_SHORT[wave],
    count: counts[wave] ?? 0,
  }));
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
        <XAxis dataKey="name" tick={{ fontSize: 11 }} interval={0} />
        <YAxis allowDecimals={false} tick={{ fontSize: 11 }} width={32} />
        <Tooltip />
        <Bar dataKey="count" isAnimationActive={false}>
          {data.map((entry) => (
            <Cell key={entry.key} fill={WAVE_COLOR[entry.key]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
