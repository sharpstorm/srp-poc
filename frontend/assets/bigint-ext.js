function n(n){return n>=0?n:-n}function t(n){if("number"==typeof n&&(n=BigInt(n)),1n===n)return 1;let t=1;do{t++}while((n>>=1n)>1n);return t}function r(n,t){if("number"==typeof n&&(n=BigInt(n)),"number"==typeof t&&(t=BigInt(t)),n<=0n||t<=0n)throw new RangeError("a and b MUST be > 0");let r=0n,e=1n,o=1n,i=0n;for(;0n!==n;){const u=t/n,f=t%n,g=r-o*u,c=e-i*u;t=n,n=f,r=o,e=i,o=g,i=c}return{g:t,x:r,y:e}}function e(n,t){if("number"==typeof n&&(n=BigInt(n)),"number"==typeof t&&(t=BigInt(t)),t<=0n)throw new RangeError("n must be > 0");const r=n%t;return r<0n?r+t:r}function o(n,t){const o=r(e(n,t),t);if(1n!==o.g)throw new RangeError(`${n.toString()} does not have inverse modulo ${t.toString()}`);return e(o.x,t)}function i(n,t,r){if(n.length!==t.length)throw new RangeError("The remainders and modulos arrays should have the same length");const i=r??t.reduce(((n,t)=>n*t),1n);return t.reduce(((t,r,u)=>{const f=i/r;return e(t+f*o(f,r)%i*n[u]%i,i)}),0n)}function u(t,r){let e="number"==typeof t?BigInt(n(t)):n(t),o="number"==typeof r?BigInt(n(r)):n(r);if(0n===e)return o;if(0n===o)return e;let i=0n;for(;0n===(1n&(e|o));)e>>=1n,o>>=1n,i++;for(;0n===(1n&e);)e>>=1n;do{for(;0n===(1n&o);)o>>=1n;if(e>o){const n=e;e=o,o=n}o-=e}while(0n!==o);return e<<i}function f(t,r){return"number"==typeof t&&(t=BigInt(t)),"number"==typeof r&&(r=BigInt(r)),0n===t&&0n===r?BigInt(0):n(t/u(t,r)*r)}function g(n,t){return n>=t?n:t}function c(n,t){return n>=t?t:n}function m(n,t){const r=BigInt(t);return e(n.map((n=>BigInt(n)%r)).reduce(((n,t)=>n+t%r),0n),r)}function p(n,t){const r=BigInt(t);return e(n.map((n=>BigInt(n)%r)).reduce(((n,t)=>n*t%r),1n),r)}function a(n){return n.map((n=>n[0]**(n[1]-1n)*(n[0]-1n))).reduce(((n,t)=>t*n),1n)}function s(t,r,u,f){if("number"==typeof t&&(t=BigInt(t)),"number"==typeof r&&(r=BigInt(r)),"number"==typeof u&&(u=BigInt(u)),u<=0n)throw new RangeError("n must be > 0");if(1n===u)return 0n;if(t=e(t,u),r<0n)return o(s(t,n(r),u,f),u);if(void 0!==f)return function(n,t,r,e){const o=e.map((n=>n[0]**n[1])),u=e.map((n=>a([n]))),f=u.map(((r,e)=>s(n,t%r,o[e])));return i(f,o,r)}(t,r,u,function(n){const t={};return n.forEach((n=>{if("bigint"==typeof n||"number"==typeof n){const r=String(n);void 0===t[r]?t[r]={p:BigInt(n),k:1n}:t[r].k+=1n}else{const r=String(n[0]);void 0===t[r]?t[r]={p:BigInt(n[0]),k:BigInt(n[1])}:t[r].k+=BigInt(n[1])}})),Object.values(t).map((n=>[n.p,n.k]))}(f));let g=1n;for(;r>0;)r%2n===1n&&(g=g*t%u),r/=2n,t=t**2n%u;return g}export{n as abs,t as bitLength,i as crt,r as eGcd,u as gcd,f as lcm,g as max,c as min,m as modAdd,o as modInv,p as modMultiply,s as modPow,a as phi,e as toZn};