rule Trojan_Linux_CloakNDag_A_2147889551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CloakNDag.A!MTB"
        threat_id = "2147889551"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CloakNDag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "transport" ascii //weight: 1
        $x_1_2 = "UserAgent" ascii //weight: 1
        $x_1_3 = "sessionId" ascii //weight: 1
        $x_1_4 = "golang.org/x/crypto/chacha20poly1305" ascii //weight: 1
        $x_1_5 = "os/exec.Command" ascii //weight: 1
        $x_1_6 = "os.startProcess" ascii //weight: 1
        $x_1_7 = "http.socksUsernamePassword" ascii //weight: 1
        $x_1_8 = "main.readDir" ascii //weight: 1
        $x_1_9 = "main.runCommand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

