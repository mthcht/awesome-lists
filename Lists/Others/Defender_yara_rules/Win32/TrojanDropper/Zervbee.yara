rule TrojanDropper_Win32_Zervbee_A_2147731276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zervbee.A!attk"
        threat_id = "2147731276"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zervbee"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "..$a.length];[io.file]::WriteAllbytes($t+'\\.vbe',$q);CsCrIpT $t'\\.vbe'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

