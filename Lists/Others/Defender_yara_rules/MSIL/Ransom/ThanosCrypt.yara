rule Ransom_MSIL_ThanosCrypt_PA_2147773696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ThanosCrypt.PA!MTB"
        threat_id = "2147773696"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ThanosCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".secure[milleni5000@qq.com]" wide //weight: 1
        $x_1_2 = "\\RESTORE_FILES_INFO.txt" wide //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "L2MgcmQgL3MgL3EgJVNZU1RFTURSSVZFJVxcJFJlY3ljbGUuYmlu" wide //weight: 1
        $x_1_5 = "WW91ciBmaWxlcyBhcmUgc2VjdXJlZC4uLg0KbWlsbGVuaTUwMDBAcXEuY29t" wide //weight: 1
        $x_1_6 = "ZGVsZXRlICJIS0NVXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1biIgL1YgIlJhY2NpbmUgVHJheSIgL0Y=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

