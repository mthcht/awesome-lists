rule Backdoor_Win32_Nanocore_G_2147742603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nanocore.G!MTB"
        threat_id = "2147742603"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( \"U\" & \"B\" & \"o\" & \"u\" & \"n\" & \"d\" " ascii //weight: 1
        $x_1_2 = "( \"S\" & \"l\" & \"e\" & \"e\" & \"p\" )" ascii //weight: 1
        $x_1_3 = "( \"S\" & \"h\" & \"e\" & \"l\" & \"l\" & \"E\" & \"x\" & \"e\" & \"c\" & \"u\" & \"t\" & \"e\" )" ascii //weight: 1
        $x_1_4 = "( \"I\" & \"s\" & \"A\" & \"d\" & \"m\" & \"i\" & \"n\" )" ascii //weight: 1
        $x_1_5 = "( \"E\" & \"v\" & \"a\" & \"l\" )" ascii //weight: 1
        $x_1_6 = "( \"@\" & \"H\" & \"o\" & \"m\" & \"e\" & \"D\" & \"r\" & \"i\" & \"v\" & \"e\" )" ascii //weight: 1
        $x_1_7 = "( \"@\" & \"S\" & \"c\" & \"r\" & \"i\" & \"p\" & \"t\" & \"D\" & \"i\" & \"r\" )" ascii //weight: 1
        $x_1_8 = "( \"b\" & \"i\" & \"n\" & \"a\" & \"r\" & \"y\" & \"t\" & \"o\" & \"s\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" )" ascii //weight: 1
        $x_1_9 = "DLLCALL ( \"shlwapi.dll\" , \"bool\" , \"PathIsDirectoryW\" , \"wstr\" , $SFILEPATH )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

