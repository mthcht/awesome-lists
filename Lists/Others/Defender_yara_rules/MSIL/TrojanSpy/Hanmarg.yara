rule TrojanSpy_MSIL_Hanmarg_A_2147730283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Hanmarg.A!bit"
        threat_id = "2147730283"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hanmarg"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\nod32kui.exe" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "https://dav.messagingengine.com/guess515.fastmail.fm/files" wide //weight: 1
        $x_1_4 = "EmailPasswords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

