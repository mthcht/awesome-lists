rule Ransom_Win32_OutSideCrypt_PA_2147776290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/OutSideCrypt.PA!MTB"
        threat_id = "2147776290"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "OutSideCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".crypt" wide //weight: 1
        $x_1_2 = "\\spoolssv.pdb" ascii //weight: 1
        $x_1_3 = "READ.txt" ascii //weight: 1
        $x_1_4 = "ALL DATA IS ENCRYPTED" ascii //weight: 1
        $x_1_5 = "rd /q /s \"%systemdrive%\\$Recycle.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

