rule VirTool_Win32_Bofadreq_A_2147901294_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bofadreq.A"
        threat_id = "2147901294"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bofadreq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cert.testrange.local" ascii //weight: 1
        $x_1_2 = "CertRequest2->lpVtbl->GetRequestId()" ascii //weight: 1
        $x_5_3 = "adcs_request SUCCESS" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

