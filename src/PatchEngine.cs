// Binary patch profile for UniVPN 10781.19.0.1214.
// Only byte-identical supported inputs are accepted. No vendor binary is bundled.
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
namespace UniVpnMulti {
 public static class BinaryPatch {
  static readonly Encoding Latin = Encoding.GetEncoding(28591);
  public static string Hash(byte[] b) {
   using(var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(b)).Replace("-","").ToLowerInvariant();
  }
  static uint U32(byte[] b,int o) {return BitConverter.ToUInt32(b,o);}
  static void Put(byte[] b,int o,uint v) {Array.Copy(BitConverter.GetBytes(v),0,b,o,4);}
  static int Pe(byte[] b) {
   if(b.Length<64 || b[0]!=77 || b[1]!=90) throw new Exception("Not a PE file");
   int p=checked((int)U32(b,60));
   if(U32(b,p)!=0x4550) throw new Exception("Invalid PE signature");
   return p;
  }
  static ulong Base(byte[] b) {int p=Pe(b)+24; return BitConverter.ToUInt16(b,p)==0x20b ? BitConverter.ToUInt64(b,p+24) : U32(b,p+28);}
  static int Sections(byte[] b) {int p=Pe(b);return p+24+BitConverter.ToUInt16(b,p+20);}
  static int Offset(byte[] b,uint va) {
   ulong r=(ulong)va-Base(b); int p=Pe(b), s=Sections(b);
   for(int i=0;i<BitConverter.ToUInt16(b,p+6);i++,s+=40) {
    uint start=U32(b,s+12), size=U32(b,s+16);
    if(r>=start && r<start+size) return checked((int)(U32(b,s+20)+r-start));
   }
   throw new Exception("Address outside mapped sections");
  }
  static void Word(byte[] b,int offset,uint before,uint after) {
   if(U32(b,offset)!=before) throw new Exception("Unexpected bytes at "+offset.ToString("x"));
   Put(b,offset,after);
  }
  static byte[] Names(byte[] b) {
   string all=Latin.GetString(b);
   foreach(var enc in new[]{Encoding.ASCII,Encoding.Unicode}) {
    string[] old={"UniVPN","Univpn","Global\\SVN"};
    string[] next={"UniVP2","Univp2","Global\\TVN"};
    for(int i=0;i<old.Length;i++) all=all.Replace(Latin.GetString(enc.GetBytes(old[i])),Latin.GetString(enc.GetBytes(next[i])));
   }
   return Latin.GetBytes(all);
  }
  static uint Payload(byte[] b,string guid) {
   int p=Pe(b),s=Sections(b);
   byte[] payload=Encoding.ASCII.GetBytes(guid.ToUpperInvariant()+"\0"+guid.ToLowerInvariant()+"\0");
   for(int i=0;i<BitConverter.ToUInt16(b,p+6);i++,s+=40) {
    if(Encoding.ASCII.GetString(b,s,8).TrimEnd('\0')!=".rdata") continue;
    uint used=U32(b,s+8),size=U32(b,s+16); int offset=checked((int)(U32(b,s+20)+used));
    if(size<used+payload.Length) throw new Exception("Insufficient .rdata padding");
    for(int n=0;n<payload.Length;n++) if(b[offset+n]!=0) throw new Exception("Padding is not empty");
    Array.Copy(payload,0,b,offset,payload.Length); Put(b,s+8,used+(uint)payload.Length);
    return checked((uint)(Base(b)+U32(b,s+12)+used));
   }
   throw new Exception("No .rdata section");
  }
  static void Pointer(byte[] b,uint va,uint before,uint after,bool x64) {
   int offset=Offset(b,va);
   if(x64) {
    if(b[offset]!=0x48 || b[offset+1]!=0x8d || b[offset+2]!=0x15) throw new Exception("Expected LEA RDX instruction");
    Word(b,offset+3,unchecked(before-va-7),unchecked(after-va-7));
   } else {
    if(b[offset]!=0xc7 || b[offset+1]!=0x44 || b[offset+2]!=0x24 || b[offset+3]!=4) {
     if(b[offset]!=0xc7 || b[offset+1]!=0x04 || b[offset+2]!=0x24) {
      if(b[offset]!=0xc7 || b[offset+1]!=0x44 || b[offset+2]!=0x24 || b[offset+3]!=8) throw new Exception("Expected MOV instruction");
     }
    }
    int immediate=b[offset+1]==0x04 ? 3 : 4;
    Word(b,offset+immediate,before,after);
   }
  }
  public static byte[] Patch(byte[] original,int kind,string guid) {
   string[] sourceHashes={
    "24f90f30309ad4bcd6c2e81adf39e44a690c648d13455194971c01a08ad0d0b1",
    "e038021b055e659430876a7e270c6ef8e8f32346155c3197cc6e539477141b10",
    "cf07de7e0ffeb470859a5df8cbc33915ef642b407c7b42627ced94f5e166ec39"};
   string[] intermediate={
    "56e6b9b4562ba959ba493b1c7e7f858aefdc1b97a980ddf8c6597f1ec7907e5b",
    "54f44a7c4d740a31b70b7f0a6496792703f4ed107e91e41e823bb3ec48f0781e",
    "e8b4542b61468577032adbf75a16d776c9a213c2cc022f4f620fd986e33ee892"};
   if(Hash(original)!=sourceHashes[kind]) throw new Exception("Unsupported UniVPN binary/version. No patch applied.");
   byte[] b=Names(original);
   int[] ports={0xb0962,0x12f9f,0x49c96};
   uint oldPort=kind==2 ? 19060U : 29190U;
   Word(b,ports[kind],oldPort,oldPort+1);
   if(Hash(b)!=intermediate[kind]) throw new Exception("Intermediate patch hash mismatch");
   if(kind==1) return b;
   uint upper=Payload(b,guid),lower=upper+(uint)guid.Length+1;
   if(kind==0) {
    Pointer(b,0x41b143,0x5b334e,0x64cd7b,false);
    Pointer(b,0x4b3920,0x64cd59,0x64cd7b,false);
    Pointer(b,0x41b1c3,0x5b335a,upper,false);
    Pointer(b,0x4b39a2,0x64cd65,lower,false);
   } else {
    Pointer(b,0x4b3843,0x5fddf0,0x5fb7ef,true);
    Pointer(b,0x4b412e,0x5fb7cd,0x5fb7ef,true);
    Pointer(b,0x4b7b8e,0x5fddf0,0x5fb7ef,true);
    Pointer(b,0x4b387e,0x5fc766,upper,true);
    Pointer(b,0x4b41b5,0x5fb7d9,lower,true);
    Pointer(b,0x4b7bc9,0x5fc766,upper,true);
   }
   return b;
  }

  public static byte[] PatchInstance(byte[] original,int kind,string guid,int number) {
   if(number<2 || number>999) throw new Exception("Instance number out of range");
   guid=new Guid(guid).ToString("B").ToUpperInvariant();
   byte[] b=Patch(original,kind,guid);
   string product="UVP"+number.ToString("D3");
   string all=Latin.GetString(b);
   foreach(var enc in new[]{Encoding.ASCII,Encoding.Unicode}) {
    string[] old={"UniVP2","Univp2","Global\\TVN"};
    string[] next={product,product,"Global\\"+number.ToString("D3")};
    for(int i=0;i<old.Length;i++) all=all.Replace(Latin.GetString(enc.GetBytes(old[i])),Latin.GetString(enc.GetBytes(next[i])));
   }
   b=Latin.GetBytes(all);
   int[] ports={0xb0962,0x12f9f,0x49c96};
   uint originalPort=kind==2 ? 19060U : 29190U;
   Word(b,ports[kind],originalPort+1,originalPort+(uint)number-1);
   return b;
  }

 }
}
