rule Trojan_Win64_Dizzyvoid_C_2147814877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dizzyvoid.C!dha"
        threat_id = "2147814877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dizzyvoid"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HttpAddUrl failed with %lu" ascii //weight: 1
        $x_1_2 = "c:\\windows\\temp\\font.tmp" ascii //weight: 1
        $x_1_3 = "MapViewOfFile failed.[%d]" ascii //weight: 1
        $x_1_4 = "It's Not PE File.[%d]" ascii //weight: 1
        $x_1_5 = ".codata" ascii //weight: 1
        $x_1_6 = "jfkdjveujvpdfjgd34=-321" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Dizzyvoid_D_2147814878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dizzyvoid.D!dha"
        threat_id = "2147814878"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dizzyvoid"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aabbddgghhkkmmnnppssuuvvyyzz||" ascii //weight: 1
        $x_1_2 = "Global\\run_%d" ascii //weight: 1
        $x_1_3 = "jfkdjveujvpdfjgd34=-321" ascii //weight: 1
        $x_1_4 = "ApacheDoFilter.dll" ascii //weight: 1
        $x_1_5 = "StartWork" ascii //weight: 1
        $x_1_6 = "apr_brigade_create" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Dizzyvoid_E_2147814879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dizzyvoid.E!dha"
        threat_id = "2147814879"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dizzyvoid"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://+:%d/%s" wide //weight: 1
        $x_1_2 = "http://+:%d/%s" wide //weight: 1
        $x_1_3 = "ERROR_IO_PENDING" ascii //weight: 1
        $x_1_4 = "jfkdjveujvpdfjgd34=-321" ascii //weight: 1
        $x_1_5 = "c:\\windows\\temp\\font.tmp" ascii //weight: 1
        $x_1_6 = "9&mNF8^K3iFUtsp4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Dizzyvoid_F_2147814880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dizzyvoid.F!dha"
        threat_id = "2147814880"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dizzyvoid"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\%s" ascii //weight: 1
        $x_1_2 = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789" ascii //weight: 1
        $x_1_3 = "httpd.exe" ascii //weight: 1
        $x_1_4 = "StartWork" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

