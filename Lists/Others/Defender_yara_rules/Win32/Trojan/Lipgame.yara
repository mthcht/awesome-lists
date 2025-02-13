rule Trojan_Win32_Lipgame_BR_2147574439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lipgame.BR"
        threat_id = "2147574439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lipgame"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /k echo FO%sR%sMAT%s vol%sume %s" ascii //weight: 1
        $x_1_2 = "%s\\PO%sOT.lnk" ascii //weight: 1
        $x_1_3 = "/k echo FORMAT volume [/FS:file-system] [/V:label] [/Q] [/A:size] [/C] [/X]" ascii //weight: 1
        $x_1_4 = "http://xdl.www2.inkont.com/kb2.php?cust=%d&w=%s&v=%s&m=%d&e=%d" ascii //weight: 1
        $x_1_5 = "%s\\Micro%sntiSp%s" ascii //weight: 1
        $x_1_6 = "SOFTWAR%sICRO%s\\WIN%sDOWS\\C%sENT%sSION\\%sphon%se%sings\\" ascii //weight: 1
        $x_1_7 = "%s\\Popup%s" ascii //weight: 1
        $x_1_8 = "=H=R=a=k=x=" ascii //weight: 1
        $x_1_9 = "\\internt.exe" ascii //weight: 1
        $x_1_10 = "%s\\swi%sag%s%sxt" ascii //weight: 1
        $x_1_11 = "%s\\K%s%s22%s.log" ascii //weight: 1
        $x_1_12 = "Lip%sGame" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

