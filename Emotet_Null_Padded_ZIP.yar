/* 

  YARA rule to highlight .ZIP files containing evidence of a large volume of compressed null bytes, a tactic often used by Emotet
  
 */

rule Emotet_Null_Padded_ZIP
{
    strings:
        $zip_header = {50 4B 03 04}

        $a1 = { AA 2A EC C1 81 00 00 00 00 00 90 FF 6B 23 A8 AA AA }
        $a2 = { AA AA 0A 7B 70 20 00 00 00 00 00 E4 FF DA 08 AA AA }
        $a3 = { AA AA C2 1E 1C 08 00 00 00 00 00 F9 BF 36 82 AA AA }
        $a4 = { AA AA B0 07 07 02 00 00 00 00 40 FE AF 8D A0 AA AA }
        $a5 = { AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA }

    condition:
        filesize < 1MB and
        $zip_header at 0 and
        all of ($a*)
}
