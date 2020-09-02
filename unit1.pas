unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics,
  Dialogs, StdCtrls, ComCtrls, tweetnacl, strutils, base64;

type

  { TForm1 }

  TForm1 = class(TForm)
    Button1: TButton;
    Button10: TButton;
    Button11: TButton;
    Button12: TButton;
    Button13: TButton;
    Button14: TButton;
    Button15: TButton;
    Button16: TButton;
    Button17: TButton;
    Button18: TButton;
    Button20: TButton;
    Button21: TButton;
    Button3: TButton;
    datamemo: TMemo;
    dec64Button: TButton;
    Edit1: TEdit;
    Edit10: TEdit;
    Edit11: TEdit;
    Edit12: TEdit;
    Edit13: TEdit;
    Edit2: TEdit;
    Edit3: TEdit;
    Edit4: TEdit;
    Edit5: TEdit;
    Edit6: TEdit;
    Edit7: TEdit;
    Edit8: TEdit;
    Edit9: TEdit;
    enc64Button: TButton;
    hashButton: TButton;
    Label10: TLabel;
    Label11: TLabel;
    Label12: TLabel;
    Label13: TLabel;
    Label14: TLabel;
    Label15: TLabel;
    Label16: TLabel;
    Label17: TLabel;
    Label18: TLabel;
    Label19: TLabel;
    Label20: TLabel;
    Label21: TLabel;
    Label22: TLabel;
    Label3: TLabel;
    Label5: TLabel;
    Label9: TLabel;
    Memo2: TMemo;
    Memo3: TMemo;
    Memo4: TMemo;
    Memo5: TMemo;
    OpenDialog1: TOpenDialog;
    PageControl1: TPageControl;
    PageControl2: TPageControl;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    TabSheet4: TTabSheet;
    TabSheet5: TTabSheet;
    TabSheet6: TTabSheet;
    TabSheet7: TTabSheet;
    procedure Button10Click(Sender: TObject);
    procedure Button11Click(Sender: TObject);
    procedure Button12Click(Sender: TObject);
    procedure Button13Click(Sender: TObject);
    procedure Button14Click(Sender: TObject);
    procedure Button15Click(Sender: TObject);
    procedure Button16Click(Sender: TObject);
    procedure Button17Click(Sender: TObject);
    procedure Button18Click(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button20Click(Sender: TObject);
    procedure Button21Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button7Click(Sender: TObject);
    procedure datamemoKeyUp(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure enc64ButtonClick(Sender: TObject);
    procedure dec64ButtonClick(Sender: TObject);
    procedure hashButtonClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private

  public

  end;

var
  Form1: TForm1;

implementation

{$R *.lfm}

{ TForm1 }

procedure TForm1.FormCreate(Sender: TObject);
begin
  randomize();
end;

procedure TForm1.Button20Click(Sender: TObject);
var
  sk, pk : string;
  m, c : string;
  n : string;
begin
  SetLength(c, crypto_box_BOXZEROBYTES);
  FillChar(c[1],crypto_box_BOXZEROBYTES,0);
  c += DecodeStringBase64(Memo5.Lines.Text);
  n := DecodeStringBase64(Edit10.Text);
  sk := DecodeStringBase64(Edit11.Text);
  pk := DecodeStringBase64(Edit9.Text);
  if (Length(sk)<>crypto_box_SECRETKEYBYTES)OR
     (Length(pk)<>crypto_box_PUBLICKEYBYTES)OR
     (Length(n)<>crypto_box_NONCEBYTES) then begin
    ShowMessage('error');
    exit();
  end;
  SetLength(m, Length(c));
  crypto_box_open(@m[1], @c[1], Length(m), @n[1], @pk[1], @sk[1]);
  Delete(m, 1, crypto_box_ZEROBYTES);
  Memo5.Lines.Text := m;
end;

procedure TForm1.Button21Click(Sender: TObject);
var
  sk, pk : string;
  m, c : string;
  n : string;
  mlen : LongWord;
begin
  SetLength(m, crypto_box_ZEROBYTES);
  FillChar(m[1], crypto_box_ZEROBYTES, 0);
  m += Memo5.Lines.Text;
  n := DecodeStringBase64(Edit10.Text);
  sk := DecodeStringBase64(Edit11.Text);
  pk := DecodeStringBase64(Edit9.Text);
  if (Length(sk)<>crypto_box_SECRETKEYBYTES)OR
     (Length(pk)<>crypto_box_PUBLICKEYBYTES)OR
     (Length(n)<>crypto_box_NONCEBYTES) then begin
    ShowMessage('error');
    exit();
  end;
  SetLength(c,Length(m));
  crypto_box(@c[1], @m[1], Length(m), @n[1], @pk[1], @sk[1]);
  Delete(c, 1, crypto_box_BOXZEROBYTES);
  Memo5.Lines.Text := EncodeStringBase64(c);
end;

procedure TForm1.Button3Click(Sender: TObject);
var
  sk, pk : string;
begin
  SetLength(sk, crypto_box_SECRETKEYBYTES);
  SetLength(pk, crypto_box_PUBLICKEYBYTES);
  crypto_box_keypair(@pk[1], @sk[1]);
  Edit11.Text := EncodeStringBase64(sk);
  Edit12.Text := EncodeStringBase64(pk);
end;

procedure TForm1.Button10Click(Sender: TObject);
var
  m, sm : string;
  sk : string;
  smlen : UInt64;
begin
  m := Memo2.Lines.Text;
  sk := DecodeStringBase64(Edit1.Text);
  if (Length(sk)<>crypto_sign_SECRETKEYBYTES) then begin
    ShowMessage('Secret Key error.');
    exit;
  end;
  SetLength(sm, Length(m) + crypto_sign_BYTES);
  crypto_sign(@sm[1], @smlen, @m[1], Length(m), @sk[1]);
  SetLength(sm, 64);
  Edit2.Text := EncodeStringBase64(sm);
end;

procedure TForm1.Button11Click(Sender: TObject);
var
  m, sm : string;
  sk : string;
  smlen : UInt64;
  F : TFileStream;
begin
  if OpenDialog1.Execute=false then exit;
  F := TFileStream.Create(OpenDialog1.FileName, fmOpenRead);
  SetLength(m, F.Size);
  F.ReadBuffer(m[1], F.Size);
  F.Free;
  sk := DecodeStringBase64(Edit1.Text);
  if (Length(sk)<>crypto_sign_SECRETKEYBYTES) then begin
    ShowMessage('Secret Key error.');
    exit;
  end;
  SetLength(sm, Length(m) + crypto_sign_BYTES);
  crypto_sign(@sm[1], @smlen, @m[1], Length(m), @sk[1]);
  SetLength(sm, 64);
  Edit2.Text := EncodeStringBase64(sm);
end;

procedure TForm1.Button12Click(Sender: TObject);
var
  m, sm : string;
  pk : string;
  mlen : UInt64;
begin
  sm := DecodeStringBase64(Edit4.Text);
  if Length(sm)<>crypto_sign_BYTES then begin
    ShowMessage('Signature error.');
    exit;
  end;
  sm += Memo3.Lines.Text;
  Memo3.Lines.Text := '';
  SetLength(m, Length(sm));
  pk := DecodeStringBase64(Edit3.Text);
  if (Length(pk)<>crypto_sign_PUBLICKEYBYTES) then begin
    ShowMessage('Public Key error.');
    exit;
  end;
  if crypto_sign_open(@m[1], @mlen, @sm[1], Length(sm), @pk[1])<>-1 then
    ShowMessage('Verified')
  else
    ShowMessage('failed');
end;

procedure TForm1.Button13Click(Sender: TObject);
var
  m, sm : string;
  pk : string;
  mlen : UInt64;
  F : TFileStream;
begin
  if OpenDialog1.Execute()=false then exit;
  sm := DecodeStringBase64(Edit4.Text);
  if Length(sm)<>crypto_sign_BYTES then begin
    ShowMessage('Signature error.');
    exit;
  end;
  F := TFileStream.Create(OpenDialog1.FileName, fmOpenRead);
  SetLength(sm, crypto_sign_BYTES + F.Size);
  F.ReadBuffer(sm[1 + crypto_sign_BYTES], F.Size);
  F.Free;
  SetLength(m, Length(sm));
  pk := DecodeStringBase64(Edit3.Text);
  if (Length(pk)<>crypto_sign_PUBLICKEYBYTES) then begin
    ShowMessage('Public Key error.');
    exit;
  end;
  if crypto_sign_open(@m[1], @mlen, @sm[1], Length(sm), @pk[1])<>-1 then
    ShowMessage('Verified')
  else
    ShowMessage('failed');
end;

procedure TForm1.Button14Click(Sender: TObject);
var
  pk, sk : string;
begin
  SetLength(pk, crypto_sign_PUBLICKEYBYTES);
  SetLength(sk, crypto_sign_SECRETKEYBYTES);
  crypto_sign_keypair(@pk[1], @sk[1]);
  Edit5.Text :=  EncodeStringBase64(sk);
  Edit6.Text :=  EncodeStringBase64(pk);
end;

procedure TForm1.Button15Click(Sender: TObject);
var
  m, c : string;
  k, n : string;
begin
  SetLength(m, crypto_secretbox_ZEROBYTES);
  FillChar(m[1], crypto_secretbox_ZEROBYTES, 0);
  m += Memo4.Lines.Text;
  k := DecodeStringBase64(Edit7.Text);
  n := DecodeStringBase64(Edit8.Text);
  SetLength(c, Length(m));
  if (crypto_secretbox(@c[1],@m[1],Length(m),@n[1],@k[1]) = 0) then begin
    Delete(c, 1, crypto_secretbox_BOXZEROBYTES);
    Memo4.Lines.Text := EncodeStringBase64(c);
  end
  else
    ShowMessage('error');
end;

procedure TForm1.Button16Click(Sender: TObject);
var
  m, c : string;
  k, n : string;
begin
  SetLength(c, crypto_secretbox_BOXZEROBYTES);
  FillChar(c[1], crypto_secretbox_BOXZEROBYTES, 0);
  c += DecodeStringBase64(Memo4.Lines.Text);
  k := DecodeStringBase64(Edit7.Text);
  n := DecodeStringBase64(Edit8.Text);
  SetLength(m, Length(c));
  if (crypto_secretbox_open(@m[1], @c[1], Length(c), @n[1], @k[1]) = 0) then begin
    Delete(m, 1, crypto_secretbox_ZEROBYTES);
    Memo4.Lines.Text := m;
  end
  else
    ShowMessage('error');
end;

procedure TForm1.Button17Click(Sender: TObject);
var
  key, nonce : string;
begin
  SetLength(key, crypto_secretbox_KEYBYTES);
  SetLength(nonce, crypto_secretbox_NONCEBYTES);
  randombytes(@key[1], crypto_secretbox_KEYBYTES);
  randombytes(@nonce[1], crypto_secretbox_NONCEBYTES);
  Edit7.Text := EncodeStringBase64(key);
  Edit8.Text := EncodeStringBase64(nonce);
end;

procedure TForm1.Button18Click(Sender: TObject);
var
  nonce : string;
begin
  SetLength(nonce, crypto_box_NONCEBYTES);
  randombytes(@nonce[1], crypto_box_NONCEBYTES);
  Edit10.Text := EncodeStringBase64(nonce);
end;

procedure TForm1.Button1Click(Sender: TObject);
var
  s, r: string;
begin
  s := DecodeStringBase64(datamemo.Lines.Text);
  SetLength(r, Length(s) * 2);
  BinToHex(@s[1], @r[1], Length(s));
  datamemo.Lines.Text := r;
end;

procedure TForm1.Button7Click(Sender: TObject);
begin

end;

procedure TForm1.datamemoKeyUp(Sender: TObject; var Key: Word;
  Shift: TShiftState);
var
  m,h : string;
  mlen: u64;
begin

  m := datamemo.Lines.Text;
  if Length(m)=0 then
    exit;
  SetLength(h,64);
  mlen := Length(m);
  if crypto_hash(@h[1], @m[1], mlen)<>0 then begin
    datamemo.Lines.Text := 'error';
    exit;
  end;
  Edit13.Text := EncodeStringBase64(h);
end;

procedure TForm1.enc64ButtonClick(Sender: TObject);
begin
  datamemo.Lines.Text := EncodeStringBase64(datamemo.Lines.Text);
end;

procedure TForm1.dec64ButtonClick(Sender: TObject);
begin
  datamemo.Lines.Text := DecodeStringBase64(datamemo.Lines.Text);
end;

procedure TForm1.hashButtonClick(Sender: TObject);
var
  m,h : string;
begin
  SetLength(h,64);
  m := datamemo.Lines.Text;
  if Length(m)=0 then exit;
  if crypto_hash(@h[1], @m[1], Length(m))<>0 then begin
    datamemo.Lines.Text := 'error';
    exit;
  end;
  Edit13.Text := EncodeStringBase64(h);
end;

end.

