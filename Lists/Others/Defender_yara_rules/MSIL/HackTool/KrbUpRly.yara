rule HackTool_MSIL_KrbUpRly_A_2147817621_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/KrbUpRly.A!dha"
        threat_id = "2147817621"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KrbUpRly"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[-] Could not connect to {0}. ldap_connect failed with error code 0x{1}" wide //weight: 1
        $x_1_2 = "[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now..." wide //weight: 1
        $x_1_3 = "[+] Rewriting function table" wide //weight: 1
        $x_1_4 = "[-] Recieved invalid apReq, exploit will fail" wide //weight: 1
        $x_1_5 = "[+] Run the spawn method for SYSTEM shell:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_MSIL_KrbUpRly_D_2147818005_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/KrbUpRly.D!dha"
        threat_id = "2147818005"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KrbUpRly"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now..." wide //weight: 1
        $x_1_2 = "[+] Computer account " wide //weight: 1
        $x_1_3 = "[+] Impersonating user '{0}' to target SPN '{1}'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_KrbUpRly_C_2147818217_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/KrbUpRly.C!dha"
        threat_id = "2147818217"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KrbUpRly"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LmPassword" wide //weight: 1
        $x_1_2 = "NtPassword" wide //weight: 1
        $x_1_3 = "Credentials" wide //weight: 1
        $x_1_4 = "Could not elevate to system" wide //weight: 1
        $x_1_5 = "(&(objectClass=computer)(sAMAccountName=" wide //weight: 1
        $x_1_6 = "DomainControllerName" ascii //weight: 1
        $x_1_7 = "PAC_WAS_REQUESTED" ascii //weight: 1
        $x_3_8 = "krbrelayup" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

