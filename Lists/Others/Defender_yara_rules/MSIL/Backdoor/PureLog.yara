rule Backdoor_MSIL_PureLog_AAA_2147968031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/PureLog.AAA!AMTB"
        threat_id = "2147968031"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$$$h$$t$tp$$$:/$/$r$e$l$a$y$-02$$$-static.network/$$rk$$ei$$/1$$208$$.b$i$n$$$" wide //weight: 10
        $x_1_2 = "\\Desktop\\2023CryptsDone\\TextEditor2\\obj\\Debug\\TextEditor.pdb" ascii //weight: 1
        $x_1_3 = "TextEditor.exe" ascii //weight: 1
        $x_1_4 = "System.Xml.Serialization" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

