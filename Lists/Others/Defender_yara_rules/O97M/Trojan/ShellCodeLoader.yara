rule Trojan_O97M_ShellCodeLoader_SS_2147982900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/ShellCodeLoader.SS!MTB"
        threat_id = "2147982900"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ShellCodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "enc = B64Decode(GetEncrypted())" ascii //weight: 1
        $x_1_2 = "k = B64Decode(GetKey())" ascii //weight: 1
        $x_1_3 = "shellcode = DecryptXor(enc, k)" ascii //weight: 1
        $x_1_4 = "mem = VirtualAlloc(0, shellLen, MEM_COMMIT Or MEM_RESERVE, PAGE_EXECUTE_READWRITE)" ascii //weight: 1
        $x_1_5 = "CopyMemory mem, shellcode(0), shellLen" ascii //weight: 1
        $x_1_6 = "result(i) = enc(i) Xor k(i Mod keyLen)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

