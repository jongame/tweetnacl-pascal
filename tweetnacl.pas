unit tweetnacl;

{$IFDEF FPC}
  {$mode objfpc}{$H+}{$Q-}
{$ELSE}
  {$POINTERMATH ON}
{$ENDIF}


interface

uses
  Classes, SysUtils, Math;

type
  u8  = UInt8;
  u32 = UInt64;
  u64 = UInt64;
  i8 = Int8;
  i32 = Int32;
  i64 =  Int64;
  pu8 = ^u8;
  pu32 = pUInt64;
  pu64 = pUInt64;
  pi64 = pInt64;
  gf = array[0..15] of i64;
  gf4 = array[0..3] of gf;
  i6464 = array[0..63] of i64;
  pgf = ^gf;

procedure randombytes(data : pu8; size : u64);
function crypto_hash(outd : pu8; m : pu8; n : u64):i32;
function crypto_scalarmult_base(q : pu8; const n : pu8):i32;
function crypto_box(c : pu8; const m : pu8; d : u64; const n : pu8; const y : pu8; const x : pu8):i32;
function crypto_box_open(m : pu8; const c : pu8; d : u64; const n : pu8; const y : pu8; const x : pu8):i32;
function crypto_box_keypair(y : pu8; x : pu8):i32;
function crypto_sign_keypair(pk : pu8; sk : pu8):i32;
function crypto_sign(sm : pu8; smlen : pu64; const m : pu8; n : u64; const sk : pu8):i32;
function crypto_sign_open(m : pu8; mlen : pu64; const sm : pu8; n : u64; const pk : pu8):i32;
function crypto_secretbox(c : pu8; const m : pu8; d : u64; const n : pu8; const k : pu8):i32;
function crypto_secretbox_open(m : pu8; const c : pu8; d : u64; const n : pu8; const k : pu8):i32;

const
  crypto_box_PUBLICKEYBYTES  = 32;
  crypto_box_SECRETKEYBYTES  = 32;
  crypto_box_NONCEBYTES = 24;
  crypto_box_ZEROBYTES = 32;
  crypto_box_BOXZEROBYTES = 16;
  crypto_sign_SECRETKEYBYTES = 64;
  crypto_sign_PUBLICKEYBYTES = 32;
  crypto_sign_BYTES = 64;
  crypto_secretbox_BOXZEROBYTES = 16;
  crypto_secretbox_KEYBYTES = 32;
  crypto_secretbox_NONCEBYTES = 24;
  crypto_secretbox_ZEROBYTES = 32;
  crypto_hash_sha512 = 64;

implementation

const
  _0 : array[0..15] of u8 = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
  _9 : array[0..31] of u8 = (9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
  gf0 : gf = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
  gf1 : gf = (1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
  _121665 : gf = ($DB41,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
  constD  : gf = ($78a3, $1359, $4dca, $75eb, $d8ab, $4141, $0a4d, $0070, $e898, $7779, $4079, $8cc7, $fe73, $2b6f, $6cee, $5203);
  D2 : gf = ($f159, $26b2, $9b94, $ebd6, $b156, $8283, $149a, $00e0, $d130, $eef3, $80f2, $198e, $fce7, $56df, $d9dc, $2406);
  constX  : gf = ($d51a, $8f25, $2d60, $c956, $a7b2, $9525, $c760, $692c, $dc5c, $fdd6, $e231, $c0a4, $53fe, $cd6e, $36d3, $2169);
  constY  : gf = ($6658, $6666, $6666, $6666, $6666, $6666, $6666, $6666, $6666, $6666, $6666, $6666, $6666, $6666, $6666, $6666);
  constI  : gf = ($a0b0, $4a0e, $1b27, $c4ee, $e478, $ad2f, $1806, $2f43, $d7a7, $3dfb, $0099, $2b4d, $df0b, $4fc1, $2480, $2b83);
  sigma : array[0..15] of byte = ($65,$78,$70,$61,$6E,$64,$20,$33,$32,$2D,$62,$79,$74,$65,$20,$6B); // "expand 32-byte k"
  minusp : array[0..16] of u32 = (5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252);
  constK : array[0..79] of u64 =(
    $428a2f98d728ae22, $7137449123ef65cd, $b5c0fbcfec4d3b2f, $e9b5dba58189dbbc,
    $3956c25bf348b538, $59f111f1b605d019, $923f82a4af194f9b, $ab1c5ed5da6d8118,
    $d807aa98a3030242, $12835b0145706fbe, $243185be4ee4b28c, $550c7dc3d5ffb4e2,
    $72be5d74f27b896f, $80deb1fe3b1696b1, $9bdc06a725c71235, $c19bf174cf692694,
    $e49b69c19ef14ad2, $efbe4786384f25e3, $0fc19dc68b8cd5b5, $240ca1cc77ac9c65,
    $2de92c6f592b0275, $4a7484aa6ea6e483, $5cb0a9dcbd41fbd4, $76f988da831153b5,
    $983e5152ee66dfab, $a831c66d2db43210, $b00327c898fb213f, $bf597fc7beef0ee4,
    $c6e00bf33da88fc2, $d5a79147930aa725, $06ca6351e003826f, $142929670a0e6e70,
    $27b70a8546d22ffc, $2e1b21385c26c926, $4d2c6dfc5ac42aed, $53380d139d95b3df,
    $650a73548baf63de, $766a0abb3c77b2a8, $81c2c92e47edaee6, $92722c851482353b,
    $a2bfe8a14cf10364, $a81a664bbc423001, $c24b8b70d0f89791, $c76c51a30654be30,
    $d192e819d6ef5218, $d69906245565a910, $f40e35855771202a, $106aa07032bbd1b8,
    $19a4c116b8d2d0c8, $1e376c085141ab53, $2748774cdf8eeb99, $34b0bcb5e19b48a8,
    $391c0cb3c5c95a63, $4ed8aa4ae3418acb, $5b9cca4f7763e373, $682e6ff3d6b2b8a3,
    $748f82ee5defb2fc, $78a5636f43172f60, $84c87814a1f0ab72, $8cc702081a6439ec,
    $90befffa23631e28, $a4506cebde82bde9, $bef9a3f7b2c67915, $c67178f2e372532b,
    $ca273eceea26619c, $d186b8c721c0c207, $eada7dd6cde0eb1e, $f57d4f7fee6ed178,
    $06f067aa72176fba, $0a637dc5a2c898a6, $113f9804bef90dae, $1b710b35131c471b,
    $28db77f523047d84, $32caab7b40c72493, $3c9ebe0a15c9bebc, $431d67c49c100d4c,
    $4cc5d4becb3e42b6, $597f299cfc657e2a, $5fcb6fab3ad6faec, $6c44198c4a475817);
  iv : array[0..63] of u8 = (
    $6a,$09,$e6,$67,$f3,$bc,$c9,$08,$bb,$67,$ae,$85,$84,$ca,$a7,$3b,
    $3c,$6e,$f3,$72,$fe,$94,$f8,$2b,$a5,$4f,$f5,$3a,$5f,$1d,$36,$f1,
    $51,$0e,$52,$7f,$ad,$e6,$82,$d1,$9b,$05,$68,$8c,$2b,$3e,$6c,$1f,
    $1f,$83,$d9,$ab,$fb,$41,$bd,$6b,$5b,$e0,$cd,$19,$13,$7e,$21,$79);
  L : array[0..31] of u64 = (
  $ed, $d3, $f5, $5c, $1a, $63, $12, $58, $d6, $9c,$f7, $a2, $de,
  $f9,$de, $14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, $10);

{$IF not defined(FPC)}
function SarInt64(Const a : Int64;b : Byte): Int64;
begin
  Result := (a shr b) or (( 0-((a shr 63) and 1)) shl (64-b));
end;


function SarLongint(Const a : Int32;b : Byte): Int32;
begin
  Result := (a shr b) or (( 0-((a shr 31) and 1)) shl (32-b));
end;
{$IFEND}
procedure randombytes(data : pu8; size : u64);
var
  i : i32;
begin
  for i:=0 to size-1 do
    data[i] := Random($FF);
end;

function L32(x : u32; c : i32):u32;
begin
  result := (x shl c) OR (SarInt64((x AND $ffffffff), (32 - c)));
end;

function ld32(const x : pu8):u32;
var
  u : u32;
begin
  u := x[3];
  u := (u shl 8) OR x[2];
  u := (u shl 8) OR x[1];
  result := (u shl 8) OR x[0];
end;

function dl64(const x : pu8):u64;
var
  i,u : u64;
begin
  u := 0;
  for i:=0 to 7 do
    u := (u shl 8) OR x[i];
  result := u;
end;

procedure st32(x : pu8; u : u32);
var
  i : i32;
begin
  for i:=0 to 3 do begin
    x[i] := u;
    u := SarInt64(u, 8);
  end;
end;

procedure ts64(x : pu8; u : u64);
var
  i : i32;
begin
  for i:=7 downto 0 do begin
    x[i] := u;
    u := u shr 8;
  end;
end;

function vn(const x : pu8; const y : pu8; n : i32):i32;
var
  i,d : i32;
begin
  d := 0;
  for i:=0 to n-1 do
    d := d OR (x[i] XOR y[i]);
  result := (1 AND (SarLongint((d - 1), 8))) - 1;
end;

function crypto_verify_16(const x : pu8; const y: pu8):i32;
begin
  result := vn(x,y,16);
end;

function crypto_verify_32(const x : pu8; const y: pu8):i32;
begin
  result := vn(x,y,32);
end;

procedure core(outd : pu8; const ind : pu8; const k : pu8; const c : pu8;  h : i32);
var
  w,x,y : array[0..15] of u32;
  t : array[0..3] of u32;
  i,j,m : i32;
begin

  for i:=0 to 3 do begin
    x[5*i] := ld32(c+4*i);
    x[1+i] := ld32(k+4*i);
    x[6+i] := ld32(ind+4*i);
    x[11+i] := ld32(k+16+4*i);
  end;

  for i:=0 to 15 do
    y[i] := x[i];

  for i:=0 to 19 do begin
    for j:=0 to 3 do begin
      for m:=0 to 3 do
        t[m] := x[(5*j+4*m) mod 16];
      t[1] := t[1] XOR L32(t[0]+t[3], 7);
      t[2] := t[2] XOR L32(t[1]+t[0], 9);
      t[3] := t[3] XOR L32(t[2]+t[1],13);
      t[0] := t[0] XOR L32(t[3]+t[2],18);
      for m:=0 to 3 do
        w[4*j+(j+m) mod 4] := t[m];
    end;
    for m:=0 to 15 do
      x[m] := w[m];
  end;

  if (h<>0) then begin
    for i:=0 to 15 do
      x[i] := x[i] + y[i];
    for i:=0 to 3 do begin
      x[5*i] := x[5*i] - ld32(c+4*i);
      x[6+i] := x[6+i] - ld32(ind+4*i);
    end;

    for i:=0 to 3 do begin
      st32(outd+4*i,x[5*i]);
      st32(outd+16+4*i,x[6+i]);
    end;
  end else
    for i:=0 to 15 do
      st32(outd + 4 * i,x[i] + y[i]);
end;

function crypto_core_salsa20(outd : pu8; const ind : pu8; const k : pu8; const c : pu8):i32;
begin
  core(outd,ind,k,c,0);
  result := 0;
end;

function crypto_core_hsalsa20(outd : pu8; const ind : pu8; const k : pu8; const c : pu8):i32;
begin
  core(outd,ind,k,c,1);
  result := 0;
end;

function crypto_stream_salsa20_xor(c : pu8; m : pu8; b : u64; const n : pu8; const k : pu8):i32;
var
  z : array[0..15] of u8;
  x : array[0..63] of u8;
  u,i : u32;
begin
  if (b=0) then exit(0);
  for i:=0 to 15 do
    z[i] := 0;
  for i:=0 to 7 do
    z[i] := n[i];
  while (b >= 64) do begin
    crypto_core_salsa20(@x,@z,k,@sigma);
    for i:=0 to 63 do
      if (m<>nil) then
        c[i] := m[i] XOR x[i]
      else
        c[i] := 0 XOR x[i];

    u := 1;
    for i:=8 to 15 do begin
      u := u + z[i];
      z[i] := u;
      u := u shr 8;
    end;
    b := b - 64;
    c := c + 64;
    if (m<>nil) then
      m := m + 64;
  end;
  if (b<>0) then begin
    crypto_core_salsa20(@x,@z,k,@sigma);
    for i:=0 to b-1 do
      if (m<>nil) then
        c[i] := m[i] XOR x[i]
      else
        c[i] := x[i];
  end;
  result := 0;
end;

function crypto_stream_salsa20(c : pu8; d : u64; const n : pu8; const k : pu8):i32;
begin
  result := crypto_stream_salsa20_xor(c,nil,d,n,k);
end;

function crypto_stream(c : pu8; d : u64; const n : pu8; const k : pu8):i32;
var
  s : array[0..31] of u8;
begin
  crypto_core_hsalsa20(@s,n,k,@sigma);
  result := crypto_stream_salsa20(c,d,n+16,@s);
end;

function crypto_stream_xor(c : pu8; const m : pu8; d : u64; const n : pu8; const k : pu8):i32;
var
  s : array[0..31] of u8;
begin
  crypto_core_hsalsa20(@s,n,k,@sigma);
  result := crypto_stream_salsa20_xor(c,m,d,n+16,@s);
end;

procedure add1305(h : pu32; const c : pu32);
var
  j,u : u32;
begin
  u := 0;
  for j:=0 to 16 do begin
    u := u + h[j] + c[j];
    h[j] := u AND 255;
    u := u shr 8;
  end;
end;

function crypto_onetimeauth(outd : pu8; m : pu8; n : u64; const k : pu8):i32;
var
  s,i,j,u : u32;
  x,r,h,c,g : array[0..16] of u32;
begin
  for j:=0 to 16 do begin
    r[j] := 0;
    h[j] := 0;
  end;
  for j:=0 to 15 do
    r[j] := k[j];
  r[3] := r[3] AND 15;
  r[4] := r[4] AND 252;
  r[7] := r[7] AND 15;
  r[8] := r[8] AND 252;
  r[11]:= r[11] AND 15;
  r[12]:= r[12] AND 252;
  r[15]:= r[15] AND 15;
  while (n > 0) do begin
    for j:=0 to 16 do
      c[j] := 0;

    j:=0;
    while ((j < 16) AND (j < n)) do begin
      c[j] := m[j];
      inc(j);
    end;
    c[j] := 1;
    m := m + j; n := n - j;
    add1305(@h,@c);
    for i:=0 to 16 do begin
      x[i] := 0;
      for j:=0 to 16 do
        if (j <= i) then
          x[i] := x[i] + h[j] * (r[i - j])
        else
          x[i] := x[i] + h[j] * (320 * r[i + 17 - j]);
    end;
    for i:=0 to 16 do
      h[i] := x[i];
    u := 0;
    for j:=0 to 15 do begin
      u := u + h[j];
      h[j] := u AND 255;
      u := u shr 8;
    end;
    u := u + h[16];
    h[16] := u AND 3;
    u := 5 * (u shr 2);
    for j:=0 to 15 do begin
      u := u + h[j];
      h[j] := u AND 255;
      u := u shr 8;
    end;
    u := u + h[16];
    h[16] := u;
  end;
  for j:=0 to 16 do
    g[j] := h[j];
  add1305(@h,@minusp);
  s := -(h[16] shr 7);
  for j:=0 to 16 do
    h[j] := h[j] XOR (s AND (g[j] XOR h[j]));

  for j:=0 to 15 do
    c[j] := k[j + 16];
  c[16] := 0;
  add1305(@h,@c);
  for j:=0 to 15 do
    outd[j] := h[j];
  result := 0;
end;

function crypto_onetimeauth_verify(const h : pu8; const m : pu8; n : u64; const k : pu8):i32;
var
  x : array[0..15] of u8;
begin
  crypto_onetimeauth(@x,m,n,k);
  result := crypto_verify_16(h,@x);
end;

function crypto_secretbox(c : pu8; const m : pu8; d : u64; const n : pu8; const k : pu8):i32;
var
  i : i32;
begin
  if (d < 32) then exit(-1);
  crypto_stream_xor(c,m,d,n,k);
  crypto_onetimeauth(c + 16,c + 32,d - 32,c);
  for i:=0 to 15 do
    c[i] := 0;
  result := 0;
end;

function crypto_secretbox_open(m : pu8; const c : pu8; d : u64; const n : pu8; const k : pu8):i32;
var
  i : i32;
  x : array[0..31] of u8;
begin
  if (d < 32) then
    exit(-1);
  crypto_stream(@x,32,n,k);
  if (crypto_onetimeauth_verify(c + 16,c + 32,d - 32,@x) <> 0) then
    exit(-1);
  crypto_stream_xor(m,c,d,n,k);
  for i:=0 to 31 do
    m[i] := 0;
  result := 0;
end;

procedure set25519(var r : gf; const a : gf);
var
  i : i32;
begin
  for i:=0 to 15 do
    r[i] := a[i];
end;

procedure car25519(var o : gf);
var
  i : i32;
  c : i64;
begin
  for i:=0 to 15 do  begin
    o[i] := o[i] + (1 shl 16);
    c := SarInt64(o[i], 16);

    if i<15 then
      o[i+1] := o[i+1] + (c-1)
    else
      o[0] := o[0] + 38*(c-1);
    o[i] := o[i] - (c shl 16);
  end;
end;

procedure sel25519(var p : gf; var q : gf; b : i32);
var
  t,i,c : i64;
begin
  c := not(b-1);
  for i:=0 to 15 do begin
    t := c AND (p[i] XOR q[i]);
    p[i] := p[i] XOR t;
    q[i] := q[i] XOR t;
  end;
end;

procedure pack25519(o : pu8; const n : pi64);
var
  i,j,b : i32;
  m,t : gf;
begin
  for i:=0 to 15 do
    t[i] := n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for j:=0 to 1 do begin
    m[0] := t[0]-$ffed;
    for i:=1 to 14 do begin
      m[i] := t[i]-$ffff-((SarInt64(m[i-1], 16)) AND 1);
      m[i-1] := m[i-1] AND $ffff;
    end;
    m[15] := t[15]-$7fff-((SarInt64(m[14], 16)) AND 1);
    b := (SarLongint(m[15], 16)) AND 1;
    m[14] := m[14] AND $ffff;
    sel25519(t,m,1-b);
  end;
  for i:=0 to 15 do begin
    o[2*i] := t[i] AND $ff;
    o[2*i+1] := t[i] shr 8;
  end;
end;

function neq25519(const a : gf; const b : gf):i32;
var
  c,d : array[0..31] of u8;
begin
  pack25519(@c,@a);
  pack25519(@d,@b);
  result := crypto_verify_32(@c,@d);
end;

function par25519(const a : gf):u8;
var
  d : array[0..31] of u8;
begin
  pack25519(@d,@a);
  result := d[0] AND 1;
end;

procedure unpack25519(var o : gf; const n : pu8); overload;
var
  i : i32;
begin
  for i:=0 to 15 do
    o[i] := n[2*i]+(n[2*i+1] shl 8);
  o[15] := o[15] AND $7fff;
end;

procedure unpack25519(o : pi64; const n : pu8); overload;
var
  i : i32;
begin
  for i:=0 to 15 do
    o[i] := n[2*i]+(n[2*i+1] shl 8);
  o[15] := o[15] AND $7fff;
end;

procedure A(var o : gf; const a : gf; const b : gf);
var
  i : i32;
begin
  for i:=0 to 15 do
    o[i] := a[i]+b[i];
end;

procedure Z(var o : gf; const a : gf; const b : gf);
var
  i : i32;
begin
  for i:=0 to 15 do
    o[i] := a[i]-b[i];
end;

procedure M(var o : gf; const a : gf; const b : gf);
var
  i,j : i64;
  t : array[0..30] of i64;
begin
  for i:=0 to 30 do
    t[i] := 0;
  for i:=0 to 15 do
    for j:=0 to 15 do
        t[i+j] := t[i+j] + (a[i]*b[j]);

  for i:=0 to 14 do
    t[i] := t[i] + (38*t[i+16]);

  for i:=0 to 15 do
    o[i] := t[i];
  car25519(o);
  car25519(o);
end;

procedure S(var o : gf; const a : gf);
begin
  M(o,a,a);
end;

procedure inv25519(var o : gf; const ic : gf);
var
  c, ca : gf;
  a : i32;
begin
  for a:=0 to 15 do
    ca[a] := ic[a];

  for a:=0 to 15 do
    c[a] := ic[a];

  for a:=253 downto 0 do begin
    S(c,c);
    if ((a<>2)AND(a<>4)) then
      M(c,c,ca);
  end;
  for a:=0 to 15 do
    o[a] := c[a];
end;

procedure pow2523(var o : gf; const i : gf);
var
  c : gf;
  a : i32;
begin
  for a:=0 to 15 do
    c[a] := i[a];
  for a:=250 downto 0 do begin
    S(c,c);
    if (a<>1) then
      M(c,c,i);
  end;
  for a:=0 to 15 do
    o[a] := c[a];
end;

function crypto_scalarmult(q : pu8; const n : pu8; const p : pu8):i32;
var
  _z : array[0..31] of u8;
  x : array[0..79] of i64;
  xgf : pgf;
  r : i64;
  i : i32;
  _a,b,c,d,e,f : gf;
begin

  for i:=0 to 30 do
    _z[i] := n[i];
  _z[31] := (n[31]AND 127)OR 64;
  _z[0] :=_z[0] AND 248;

  unpack25519(@x,p);
  for i:=0 to 15 do begin
    b[i] := x[i];
    d[i] := 0; _a[i] := 0; c[i] :=0;
  end;

  _a[0] := 1; d[0] := 1;
  for i:=254 downto 0 do begin
    r := (SarInt64(_z[i shr 3], (i AND 7)))AND 1;
    sel25519(_a,b,r);
    sel25519(c,d,r);
    A(e,_a,c);
    Z(_a,_a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,_a);
    M(_a,c,_a);
    M(c,b,e);
    A(e,_a,c);
    Z(_a,_a,c);
    S(b,_a);
    Z(c,d,f);
    M(_a,c,_121665);
    A(_a,_a,d);
    M(c,c,_a);
    M(_a,d,f);
    xgf := @x[0];
    M(d,b,xgf^);
    S(b,e);
    sel25519(_a,b,r);
    sel25519(c,d,r);
  end;

  for i:=0 to 15 do begin
    x[i+16] := _a[i];
    x[i+32] := c[i];
    x[i+48] := b[i];
    x[i+64] := d[i];
  end;
  inv25519(pgf(@x[32])^,pgf(@x[32])^);
  M(pgf(@x[16])^,pgf(@x[16])^,pgf(@x[32])^);

  pack25519(q,@x[16]);
  result := 0;
end;

function crypto_scalarmult_base(q : pu8; const n : pu8):i32;
begin
  result := crypto_scalarmult(q,n,@_9);
end;

function crypto_box_keypair(y : pu8; x : pu8):i32;
begin
  randombytes(x,32);
  result := crypto_scalarmult_base(y,x);
end;

function crypto_box_beforenm(k : pu8; const y : pu8; const x : pu8):i32;
var
  s : array[0..31] of u8;
begin
  crypto_scalarmult(@s,x,y);
  result := crypto_core_hsalsa20(k,@_0,@s,@sigma);
end;

function crypto_box_afternm(c : pu8; const m : pu8; d : u64; const n : pu8; const k : pu8):i32;
begin
  result := crypto_secretbox(c,m,d,n,k);
end;

function crypto_box_open_afternm(m : pu8; const c : pu8; d : u64; const n : pu8; const k : pu8):i32;
begin
  result := crypto_secretbox_open(m,c,d,n,k);
end;

function crypto_box(c : pu8; const m : pu8; d : u64; const n : pu8; const y : pu8; const x : pu8):i32;
var
  k : array[0..31] of u8;
begin
  crypto_box_beforenm(@k,y,x);
  result := crypto_box_afternm(c,m,d,n,@k);
end;

function crypto_box_open(m : pu8; const c : pu8; d : u64; const n : pu8; const y : pu8; const x : pu8):i32;
var
  k : array[0..31] of u8;
begin
  crypto_box_beforenm(@k,y,x);
  result := crypto_box_open_afternm(m,c,d,n,@k);
end;

function R(x : u64; c : i32):u64;
begin
  result :=  (x shr c) OR (x shl (64 - c));
end;

function Ch(x : u64; y : u64; z : u64):u64;
begin
  result := (x AND y) XOR (NOT(x) AND z);
end;

function Maj(x : u64; y : u64; z : u64):u64;
begin
  result := (x AND y) XOR (x AND z) XOR (y AND z);
end;

function Sigma0(x : u64):u64;
begin
  result := R(x,28) XOR R(x,34) XOR R(x,39);
end;

function Sigma1(x : u64):u64;
begin
  result := R(x,14) XOR R(x,18) XOR R(x,41);
end;

function _sigma0(x : u64):u64;
begin
  result := R(x, 1) XOR R(x, 8) XOR (x shr 7);
end;

function _sigma1(x : u64):u64;
begin
  result :=R(x,19) XOR R(x,61) XOR (x shr 6);
end;

function crypto_hashblocks(x : pu8; m : pu8; n : u64):i32;
var
  z,b,a : array[0..7] of u64;
  w : array[0..15] of u64;
  t : u64;
  i,j : i32;
begin
  for i:=0 to 7 do begin
    z[i] := dl64(x + 8 * i);
    a[i] := z[i];
  end;
  while (n >= 128) do begin
    for i:=0 to 15 do
      w[i] := dl64(m + 8 * i);
    for i:=0 to 79 do begin
      for j:=0 to 7 do
        b[j] := a[j];
      t := a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + constK[i] + w[i mod 16];
      b[7] := t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
      b[3] := b[3] + t;
      for j:=0 to 7 do
        a[(j+1)mod 8] := b[j];
      if ((i mod 16) = 15) then
	for j:=0 to 15 do
	  w[j] := w[j] + w[(j+9) mod 16] + _sigma0(w[(j+1) mod 16]) + _sigma1(w[(j+14)mod 16]);
    end;
    for i:=0 to 7 do begin
      a[i] := a[i] + z[i]; z[i] := a[i];
    end;
    m := m + 128;
    n := n - 128;
  end;
  for i:=0 to 7 do
    ts64(x+8*i,z[i]);
  result := n;
end;

function crypto_hash(outd : pu8; m : pu8; n : u64):i32;
var
  h : array[0..63] of u8;
  x : array[0..255] of u8;
  i,b : u64;
begin
  b := n;
  for i:=0 to 63 do
    h[i] := iv[i];
  crypto_hashblocks(@h,m,n);
  m := m + n;
  n := n AND 127;
  m := m - n;

  for i:=0 to 255 do
    x[i] := 0;
  if n<>0 then
    for i:=0 to n-1 do
      x[i] := m[i];
  x[n] := 128;

  if (n<112) then
    n := 256-128
  else
    n := 256;
  x[n-9] := b shr 61;
  ts64(@x[n-8],b shl 3);
  crypto_hashblocks(@h,@x,n);

  for i:=0 to 63 do
    outd[i] := h[i];
  result := 0;
end;

procedure add(var p : gf4; var q : gf4);
var
  _a,b,c,d,t,e,f,g,h : gf;
begin
  Z(_a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(_a, _a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, _a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, _a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
end;

procedure cswap(var p : gf4; var q : gf4; b : u8);
var
  i : i32;
begin
  for i:=0 to 3 do
    sel25519(p[i],q[i],b);
end;

procedure pack(r : pu8; p : gf4);
var
  tx,ty,zi : gf;
begin
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, @ty);
  r[31] := r[31] XOR par25519(tx) shl 7;
end;

procedure scalarmult(var p : gf4; var q : gf4; const s : pu8);
var
  i : i32;
  b : u8;
begin
  set25519(p[0],gf0);
  set25519(p[1],gf1);
  set25519(p[2],gf1);
  set25519(p[3],gf0);

  for i:=255 downto 0 do begin
    b := (s[i div 8] shr (i AND 7)) AND 1;
    cswap(p,q,b);
    add(q,p);
    add(p,p);
    cswap(p,q,b);
  end;
end;

procedure scalarbase(var p : gf4; const s : pu8);
var
  q : gf4;
begin
  set25519(q[0],constX);
  set25519(q[1],constY);
  set25519(q[2],gf1);
  M(q[3],constX,constY);
  scalarmult(p,q,s);
end;

function crypto_sign_keypair(pk : pu8; sk : pu8):i32;
var
  d : array[0..63] of u8;
  p : gf4;
  i : i32;
begin
  randombytes(sk, 32);
  crypto_hash(@d, sk, 32);
  d[0] := d[0] AND 248;
  d[31] := d[31] AND 127;
  d[31] := d[31] OR 64;

  scalarbase(p,@d);
  pack(pk,p);

  for i:=0 to 31 do
    sk[32 + i] := pk[i];
  result := 0;
end;

procedure modL(r : pu8; var x : i6464);
var
  carry,i,j : i64;
begin
  for i:=63 downto 32 do begin
    carry := 0;
    j := i - 32;
    while (j < (i - 12)) do begin
      x[j] := x[j] + (carry - 16 * x[i] * L[j - (i - 32)]);
      carry := SARInt64((x[j] + 128), 8);
      x[j] := x[j] - (carry shl 8);
      inc(j);
    end;
    x[j] := x[j] + carry;
    x[i] := 0;
  end;
  carry := 0;
  for j:=0 to 31 do begin
    x[j] := x[j] + (carry - SARInt64(x[31], 4) * L[j]);
    carry := SARInt64(x[j], 8);
    x[j] := x[j] AND 255;
  end;
  for j:=0 to 31 do
    x[j] := x[j] - (carry * L[j]);
  for i:=0 to 31 do begin
    x[i+1] := x[i+1] + SARInt64(x[i], 8);
    r[i] := x[i] AND 255;
  end;
end;

procedure reduce(r : pu8);
var
  x : i6464;
  i : i64;
begin
  for i:=0 to 63 do
    x[i] := u64(r[i]);
  for i:=0 to 63 do
    r[i] := 0;
  modL(r,x);

end;

function crypto_sign(sm : pu8; smlen : pu64; const m : pu8; n : u64; const sk : pu8):i32;
var
  d,h,r : array[0..63] of u8;
  i,j : i64;
  x : i6464;
  p : gf4;
begin
  crypto_hash(@d, sk, 32);
  d[0] := d[0] AND 248;
  d[31] := d[31] AND 127;
  d[31] := d[31] OR 64;

  smlen^ := n+64;

  for i:=0 to n-1 do
    sm[64 + i] := m[i];

  for i:=0 to 31 do
    sm[32 + i] := d[32 + i];

  crypto_hash(@r, sm+32, n+32);
  reduce(@r);
  scalarbase(p,@r[0]);
  pack(sm,p);

  for i:=0 to 31 do
    sm[i+32] := sk[i+32];
  crypto_hash(@h[0],sm,n + 64);
  reduce(@h[0]);

  for i:=0 to 63 do
    x[i] := 0;
  for i:=0 to 31 do
    x[i] := r[i];
  for i:=0 to 31 do
    for j:=0 to 31 do
      x[i+j] := x[i+j] + h[i] * d[j];
  modL(sm + 32,x);
  result := 0;
end;

function unpackneg(var r : gf4; const p : pu8):i32;
var
  t,chk,num,den,den2,den4,den6 : gf;
begin
  set25519(r[2],gf1);
  unpack25519(r[1],p);
  S(num,r[1]);
  M(den,num,constD);
  Z(num,num,r[2]);
  A(den,r[2],den);

  S(den2,den);
  S(den4,den2);
  M(den6,den4,den2);
  M(t,den6,num);
  M(t,t,den);

  pow2523(t,t);
  M(t,t,num);
  M(t,t,den);
  M(t,t,den);
  M(r[0],t,den);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)<>0) then
    M(r[0],r[0],constI);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)<>0) then
    exit(-1);
  if (par25519(r[0]) = (p[31] shr 7)) then
    Z(r[0],gf0,r[0]);
  M(r[3],r[0],r[1]);
  result := 0;
end;

function crypto_sign_open(m : pu8; mlen : pu64; const sm : pu8; n : u64; const pk : pu8):i32;
var
  i : i32;
  t : array[0..31] of u8;
  h : array[0..63] of u8;
  p,q : gf4;
begin
  fillchar(q,512,$FF);
  mlen^ := u64(-1);
  if (n < 64) then
    exit(-1);

  if (unpackneg(q,pk)<>0) then
    exit(-1);
  for i:=0 to n-1 do
    m[i] := sm[i];
  for i:=0 to 31 do
    m[i+32] := pk[i];

  crypto_hash(@h,m,n);

  reduce(@h);

  scalarmult(p,q,@h);
  scalarbase(q,sm + 32);

  add(p,q);
  pack(@t,p);

  n := n - 64;
  if (crypto_verify_32(sm, @t)<>0) then begin
    for i:=0 to n-1 do
      m[i] := 0;
    exit(-1);
  end;

  for i:=0 to n-1 do
    m[i] := sm[i + 64];
  mlen^ := n;
  result := 0;
end;

end.
