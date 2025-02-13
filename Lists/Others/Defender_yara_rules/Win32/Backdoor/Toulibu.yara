rule Backdoor_Win32_Toulibu_2147603364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Toulibu"
        threat_id = "2147603364"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Toulibu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft filter tools" wide //weight: 1
        $x_1_2 = "related.php" wide //weight: 1
        $x_1_3 = "Technischer Fehler" wide //weight: 1
        $x_1_4 = "Explorer\\Main\\Window Title" wide //weight: 1
        $x_1_5 = "charset=ANSI; boundary=" wide //weight: 1
        $x_1_6 = "srch.php" wide //weight: 1
        $x_1_7 = "ieframe.dll/dnserror.htm" wide //weight: 1
        $x_2_8 = "[Resived CMD]" wide //weight: 2
        $x_2_9 = "KILLWINREBOOT-" wide //weight: 2
        $x_2_10 = "IFAKER=" wide //weight: 2
        $x_2_11 = "PROCESSING:UNINSTALLING-BYE" wide //weight: 2
        $x_2_12 = "$USEITNOMORE" wide //weight: 2
        $x_2_13 = "INJECT=" wide //weight: 2
        $x_2_14 = "OLDPOSTDATA:=" wide //weight: 2
        $x_2_15 = "RXblock" ascii //weight: 2
        $x_2_16 = "RXfake" ascii //weight: 2
        $x_1_17 = "Document2_onclick" ascii //weight: 1
        $x_2_18 = "Document2_onkeypress" ascii //weight: 2
        $x_2_19 = "TargetFrameName" ascii //weight: 2
        $x_2_20 = "Zombie_GetTypeInfo" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((11 of ($x_2_*))) or
            (all of ($x*))
        )
}

