rule Trojan_Win32_Haudicx_A_2147711438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Haudicx.A!bit"
        threat_id = "2147711438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Haudicx"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\*.doc" wide //weight: 1
        $x_1_2 = "Ext = doc,pdf" ascii //weight: 1
        $x_1_3 = "FileCopy, %A_LoopFileFullPath%, %CTF%\\%A_LoopFileName%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

