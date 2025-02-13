rule Ransom_Win32_FonixCrypt_SK_2147757932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FonixCrypt.SK!MTB"
        threat_id = "2147757932"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FonixCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c vssadmin Delete Shadows /All /Quiet & wmic shadowcopy delete" ascii //weight: 1
        $x_1_2 = "Fonix" ascii //weight: 1
        $x_1_3 = "# How To Decrypt Files #.hta" ascii //weight: 1
        $x_1_4 = "Copy Cpriv.key %appdata%\\Cpriv.key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

