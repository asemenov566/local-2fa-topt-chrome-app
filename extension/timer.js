// The elapsed wedge opens clockwise from twelve; the remaining sector ends there.
export function timerSector(fraction) {
  const remaining=Math.max(0,Math.min(1,fraction));
  if(remaining<=0)return '';
  if(remaining>=1)return 'M16 0 A16 16 0 1 1 16 32 A16 16 0 1 1 16 0 Z';
  const elapsed=2*Math.PI*(1-remaining);
  const x=16+16*Math.sin(elapsed), y=16-16*Math.cos(elapsed);
  return 'M16 16 L'+x.toFixed(4)+' '+y.toFixed(4)+' A16 16 0 '+(remaining>.5?1:0)+' 1 16 0 Z';
}
