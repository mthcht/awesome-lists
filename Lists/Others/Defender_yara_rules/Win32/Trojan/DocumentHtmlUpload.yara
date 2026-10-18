rule Trojan_Win32_DocumentHtmlUpload_A_2147980538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DocumentHtmlUpload.A"
        threat_id = "2147980538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DocumentHtmlUpload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "word.application" wide //weight: 1
        $x_1_2 = ".paragraphs" wide //weight: 1
        $x_1_3 = "html.escape" wide //weight: 1
        $x_1_4 = "::readallbytes(" wide //weight: 1
        $x_1_5 = "system.net.http.bytearraycontent" wide //weight: 1
        $x_1_6 = "system.net.http.httpmethod]::post" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

