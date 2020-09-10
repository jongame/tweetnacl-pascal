program tests;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, tweetnacl;

function testSecretbox_encrypt():boolean;
const
  k : array[0..crypto_secretbox_KEYBYTES-1] of u8 = ($A8,$37,$57,$ED,$82,$63,$9A,$F6,$42,$C4,$BF,$32,$F9,$1E,$10,$23,$EE,$E4,$60,$4C,$3F,$24,$06,$3F,$F2,$E9,$71,$83,$24,$DB,$E3,$61);
  n : array[0..crypto_secretbox_NONCEBYTES-1] of u8 = ($B2,$55,$60,$11,$6A,$A5,$86,$E0,$8D,$8C,$E3,$65,$9B,$AC,$F0,$45,$DD,$15,$41,$FA,$A8,$51,$8B,$48);
  msg : array[0..11] of u8 = ($48,$65,$6C,$6C,$6F,$20,$77,$6F,$72,$6C,$64,$21);
  box : array[0..27] of u8 = ($96,$87,$CD,$2F,$8A,$87,$66,$E7,$DC,$E2,$72,$5F,$C5,$3B,$10,$07,$10,$8E,$7F,$4F,$FF,$AF,$98,$37,$B0,$38,$3E,$D5);
var
  m, c : array of u8;
  i : integer;
begin
  result := false;
  SetLength(m, crypto_secretbox_ZEROBYTES);
  FillChar(m[0], crypto_secretbox_ZEROBYTES, 0);
  m := concat(m, msg);
  SetLength(c, Length(m));
  if (crypto_secretbox(@c[0],@m[0],Length(m),@n[0],@k[0]) <> 0) then
    exit(false);
  Delete(c, 0, crypto_secretbox_BOXZEROBYTES);
  for i:=0 to High(c) do
    if c[i]<>box[i] then
      exit(false);
  result := true;
end;

function testSecretbox_decrypt():boolean;
const
  k : array[0..crypto_secretbox_KEYBYTES-1] of u8 = ($A8,$37,$57,$ED,$82,$63,$9A,$F6,$42,$C4,$BF,$32,$F9,$1E,$10,$23,$EE,$E4,$60,$4C,$3F,$24,$06,$3F,$F2,$E9,$71,$83,$24,$DB,$E3,$61);
  n : array[0..crypto_secretbox_NONCEBYTES-1] of u8 = ($B2,$55,$60,$11,$6A,$A5,$86,$E0,$8D,$8C,$E3,$65,$9B,$AC,$F0,$45,$DD,$15,$41,$FA,$A8,$51,$8B,$48);
  msg : array[0..11] of u8 = ($48,$65,$6C,$6C,$6F,$20,$77,$6F,$72,$6C,$64,$21);
  box : array[0..27] of u8 = ($96,$87,$CD,$2F,$8A,$87,$66,$E7,$DC,$E2,$72,$5F,$C5,$3B,$10,$07,$10,$8E,$7F,$4F,$FF,$AF,$98,$37,$B0,$38,$3E,$D5);
var
  m, c : array of u8;
  i : integer;
begin
  result := false;
  SetLength(c, crypto_secretbox_BOXZEROBYTES);
  FillChar(c[0], crypto_secretbox_BOXZEROBYTES, 0);
  c := concat(c, box);
  SetLength(m, Length(c));
  if (crypto_secretbox(@m[0],@c[0],Length(c),@n[0],@k[0]) <> 0) then
    exit(false);
  Delete(m, 0, crypto_secretbox_ZEROBYTES);
  for i:=0 to High(m) do
    if m[i]<>msg[i] then
      exit(false);
  result := true;
end;

function testBox_encrypt():boolean;
const
  sk : array[0..crypto_box_SECRETKEYBYTES-1] of u8 = ($73,$2F,$80,$D6,$A1,$70,$FC,$5E,$D8,$31,$E1,$F8,$2D,$81,$08,$81,$9A,$0D,$48,$4C,$59,$B6,$CB,$BF,$38,$AD,$AD,$E0,$CC,$F8,$D1,$32);
  pk : array[0..crypto_box_PUBLICKEYBYTES-1] of u8 = ($93,$F1,$42,$E4,$8B,$C6,$D4,$10,$CD,$13,$3E,$8F,$DA,$CC,$55,$66,$16,$66,$4F,$79,$6D,$12,$71,$D3,$D7,$1A,$7E,$25,$70,$BB,$B3,$2E);
  n : array[0..crypto_box_NONCEBYTES-1] of u8 = ($74,$18,$DB,$06,$AE,$EF,$10,$5F,$AE,$80,$DD,$48,$B2,$DE,$0B,$F3,$6F,$DA,$56,$81,$58,$15,$9A,$04);
  msg : array[0..11] of u8 = ($48,$65,$6C,$6C,$6F,$20,$77,$6F,$72,$6C,$64,$21);
  box : array[0..27] of u8 = ($54,$A1,$AC,$34,$08,$96,$C8,$EC,$A8,$18,$9E,$AC,$2D,$A5,$FF,$34,$C4,$0E,$7F,$8C,$48,$CC,$B2,$FC,$F1,$74,$2B,$4D);
var
  m, c : array of u8;
  i : integer;
begin
  result := false;
  SetLength(m, crypto_box_ZEROBYTES);
  FillChar(m[0], crypto_box_ZEROBYTES, 0);
  m := concat(m, msg);
  SetLength(c,Length(m));
  crypto_box(@c[0], @m[0], Length(m), @n[0], @pk[0], @sk[0]);
  Delete(c, 0, crypto_box_BOXZEROBYTES);
  for i:=0 to High(c) do
    if c[i]<>box[i] then
      exit(false);
  result := true;
end;

function testBox_decrypt():boolean;
const
  sk : array[0..crypto_box_SECRETKEYBYTES-1] of u8 = ($AB,$E7,$49,$E6,$4D,$CD,$30,$BB,$29,$CA,$ED,$9F,$3E,$A7,$C9,$5C,$D8,$DD,$98,$5B,$FA,$8B,$D1,$CD,$66,$73,$C4,$EF,$CF,$2E,$D6,$F6);
  pk : array[0..crypto_box_PUBLICKEYBYTES-1] of u8 = ($E0,$1F,$EB,$33,$47,$D8,$1C,$24,$42,$3D,$FD,$68,$CB,$62,$1D,$85,$59,$6D,$A4,$D1,$62,$01,$E1,$A1,$A5,$3A,$02,$5D,$AD,$65,$8D,$60);
  n : array[0..crypto_box_NONCEBYTES-1] of u8 = ($74,$18,$DB,$06,$AE,$EF,$10,$5F,$AE,$80,$DD,$48,$B2,$DE,$0B,$F3,$6F,$DA,$56,$81,$58,$15,$9A,$04);
  msg : array[0..11] of u8 = ($48,$65,$6C,$6C,$6F,$20,$77,$6F,$72,$6C,$64,$21);
  box : array[0..27] of u8 = ($54,$A1,$AC,$34,$08,$96,$C8,$EC,$A8,$18,$9E,$AC,$2D,$A5,$FF,$34,$C4,$0E,$7F,$8C,$48,$CC,$B2,$FC,$F1,$74,$2B,$4D);
var
  m, c : array of u8;
  i : integer;
begin
  result := false;
  SetLength(c, crypto_box_BOXZEROBYTES);
  FillChar(c[0], crypto_box_BOXZEROBYTES, 0);
  c := concat(c, box);
  SetLength(m,Length(c));
  crypto_box_open(@m[0], @c[0], Length(c), @n[0], @pk[0], @sk[0]);
  Delete(m, 0, crypto_box_ZEROBYTES);
  for i:=0 to High(m) do
    if m[i]<>msg[i] then
      exit(false);
  result := true;
end;

function testSign():boolean;
const
  sk : array[0..crypto_sign_SECRETKEYBYTES-1] of u8 = ($F4,$68,$34,$58,$67,$16,$2C,$26,$30,$56,$61,$64,$30,$27,$12,$90,$12,$01,$5A,$98,$EC,$D8,$74,$CB,$76,$4E,$4C,$EF,$39,$E2,$7C,$18,$EC,$85,$34,$D2,$28,$50,$D6,$70,$D0,$C8,$37,$92,$E9,$76,$58,$69,$B4,$D3,$F9,$92,$FE,$A1,$9A,$4E,$BE,$40,$DC,$E5,$19,$F8,$06,$CC);
  msg : array[0..11] of u8 = ($48,$65,$6C,$6C,$6F,$20,$77,$6F,$72,$6C,$64,$21);
  signature : array[0..crypto_sign_BYTES-1] of u8 = ($3F,$1A,$9D,$D0,$16,$95,$D1,$18,$C1,$87,$83,$15,$79,$8A,$8F,$58,$F3,$25,$D1,$AF,$A6,$1D,$1F,$20,$45,$23,$66,$1F,$83,$7E,$B0,$9B,$B2,$59,$87,$F1,$3F,$0E,$0B,$0E,$96,$1F,$72,$9B,$26,$52,$56,$2B,$83,$0B,$4F,$2C,$6C,$5B,$81,$66,$78,$7F,$0B,$9A,$34,$F5,$B1,$0F);
var
  sm : array of u8;
  smlen : UInt64;
  i : integer;
begin
  result := false;
  SetLength(sm, Length(msg) + crypto_sign_BYTES);
  crypto_sign(@sm[0], @smlen, @msg[0], Length(msg), @sk[0]);
  SetLength(sm, 64);
  for i:=0 to High(sm) do
    if sm[i]<>signature[i] then
      exit(false);
  result := true;
end;

function testSign_open():boolean;
const
  pk : array[0..crypto_sign_PUBLICKEYBYTES-1] of u8 = ($EC,$85,$34,$D2,$28,$50,$D6,$70,$D0,$C8,$37,$92,$E9,$76,$58,$69,$B4,$D3,$F9,$92,$FE,$A1,$9A,$4E,$BE,$40,$DC,$E5,$19,$F8,$06,$CC);
  msg : array[0..11] of u8 = ($48,$65,$6C,$6C,$6F,$20,$77,$6F,$72,$6C,$64,$21);
  signature : array[0..crypto_sign_BYTES-1] of u8 = ($3F,$1A,$9D,$D0,$16,$95,$D1,$18,$C1,$87,$83,$15,$79,$8A,$8F,$58,$F3,$25,$D1,$AF,$A6,$1D,$1F,$20,$45,$23,$66,$1F,$83,$7E,$B0,$9B,$B2,$59,$87,$F1,$3F,$0E,$0B,$0E,$96,$1F,$72,$9B,$26,$52,$56,$2B,$83,$0B,$4F,$2C,$6C,$5B,$81,$66,$78,$7F,$0B,$9A,$34,$F5,$B1,$0F);
var
  m, sm : array of u8;
  mlen : UInt64;

begin
  result := false;
  sm := signature;
  sm := concat(sm, msg);
  SetLength(m, Length(sm));
  if crypto_sign_open(@m[0], @mlen, @sm[0], Length(sm), @pk[0])<>0 then
    exit(false);
  result := true;
end;

function testHash():boolean;
const
  msg : array[0..1] of array of u8 = ((),($54,$68,$65,$20,$71,$75,$69,$63,$6B,$20,$62,$72,$6F,$77,$6E,$20,$66,$6F,$78,$20,$6A,$75,$6D,$70,$73,$20,$6F,$76,$65,$72,$20,$74,$68,$65,$20,$6C,$61,$7A,$79,$20,$64,$6F,$67));
  hash : array[0..1] of array[0..crypto_hash_sha512-1] of u8 = (($CF,$83,$E1,$35,$7E,$EF,$B8,$BD,$F1,$54,$28,$50,$D6,$6D,$80,$07,$D6,$20,$E4,$05,$0B,$57,$15,$DC,$83,$F4,$A9,$21,$D3,$6C,$E9,$CE,$47,$D0,$D1,$3C,$5D,$85,$F2,$B0,$FF,$83,$18,$D2,$87,$7E,$EC,$2F,$63,$B9,$31,$BD,$47,$41,$7A,$81,$A5,$38,$32,$7A,$F9,$27,$DA,$3E), ($07,$E5,$47,$D9,$58,$6F,$6A,$73,$F7,$3F,$BA,$C0,$43,$5E,$D7,$69,$51,$21,$8F,$B7,$D0,$C8,$D7,$88,$A3,$09,$D7,$85,$43,$6B,$BB,$64,$2E,$93,$A2,$52,$A9,$54,$F2,$39,$12,$54,$7D,$1E,$8A,$3B,$5E,$D6,$E1,$BF,$D7,$09,$78,$21,$23,$3F,$A0,$53,$8F,$3D,$B8,$54,$FE,$E6));
var
  h : array[0..crypto_hash_sha512-1] of u8;
  mlen : u64;
  i,j : integer;
begin
  result := false;
  for i:=0 to High(msg) do begin
    mlen := Length(msg[i]);
    if crypto_hash(@h[0], @msg[i][0], mlen)<>0 then
      exit(false);
    for j:=0 to crypto_hash_sha512-1 do
      if h[j]<>hash[i][j] then
        exit(false);
  end;

  result := true;
end;

begin
  write('Test Secretbox_encrypt ');
  if testSecretbox_encrypt then writeln('passed.') else writeln('error.');

  write('Test Secretbox_decrypt ');
  if testSecretbox_decrypt then writeln('passed.') else writeln('error.');

  write('Test Box_encrypt ');
  if testBox_encrypt then writeln('passed.') else writeln('error.');

  write('Test Box_decrypt ');
  if testBox_decrypt then writeln('passed.') else writeln('error.');

  write('Test sign ');
  if testSign then writeln('passed.') else writeln('error.');

  write('Test sign_open ');
  if testSign_open then writeln('passed.') else writeln('error.');

  write('Test hash ');
  if testHash then writeln('passed.') else writeln('error.');
  readln;
end.

