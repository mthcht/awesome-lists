rule PWS_MSIL_ProstoClipper_YA_2147740691_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/ProstoClipper.YA!MTB"
        threat_id = "2147740691"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ProstoClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "58"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "^((8|\\+7|\\+380|\\+375|\\+373)[\\- ]?)?(\\(?\\d{3}\\)?[\\- ]?)?[\\d\\- ]{7,10}$" wide //weight: 1
        $x_1_2 = "(^(1|3)(?=.*[0-9])(?=.*[a-zA-Z])[\\da-zA-Z]{27,34}?[\\d\\- ])|(^(1|3)(?=.*[0-9])(?=.*[a-zA-Z])[\\da-zA-Z]{27,34})$" wide //weight: 1
        $x_1_3 = "(^L[A-Za-z0-9]{32,34}?[\\d\\- ])|(^L[A-Za-z0-9]{32,34})$" wide //weight: 1
        $x_1_4 = "(^q[A-Za-z0-9\\:]{32,54}?[\\d\\- ])|(^q[A-Za-z0-9\\:]{32,54})$" wide //weight: 1
        $x_1_5 = "^(P|p){1}[0-9]?[\\d\\- ]{7,15}|.+@.+\\..+$" wide //weight: 1
        $x_1_6 = "(^0x[A-Za-z0-9]{40,40}?[\\d\\- ])|(^0x[A-Za-z0-9]{40,40})$" wide //weight: 1
        $x_1_7 = "(^X[A-Za-z0-9]{32,34}?[\\d\\- ])|(^X[A-Za-z0-9]{32,34})$" wide //weight: 1
        $x_1_8 = "^41001[0-9]?[\\d\\- ]{7,11}$" wide //weight: 1
        $x_1_9 = "^R[0-9]?[\\d\\- ]{12,13}$" wide //weight: 1
        $x_1_10 = "^Z[0-9]?[\\d\\- ]{12,13}$" wide //weight: 1
        $x_1_11 = "(^(GD|GC)[A-Z0-9]{54,56}?[\\d\\- ])|(^(GD|GC)[A-Z0-9]{54,56})$" wide //weight: 1
        $x_1_12 = "(^A[A-Za-z0-9]{32,34}?[\\d\\- ])|(^A[A-Za-z0-9]{32,34})$" wide //weight: 1
        $x_1_13 = "(^t[A-Za-z0-9]{32,36}?[\\d\\- ])|(^t[A-Za-z0-9]{32,36})$" wide //weight: 1
        $x_1_14 = "(^r[A-Za-z0-9]{32,34}?[\\d\\- ])|(^r[A-Za-z0-9]{32,34})$" wide //weight: 1
        $x_1_15 = "(^G[A-Za-z0-9]{32,35}?[\\d\\- ])|(^G[A-Za-z0-9]{32,35})$" wide //weight: 1
        $x_1_16 = "(^D[A-Za-z0-9]{32,35}?[\\d\\- ])|(^D[A-Za-z0-9]{32,35})$" wide //weight: 1
        $x_1_17 = "(^(T[A-Z])[A-Za-z0-9]{32,35}?[\\d\\- ])|(^(T[A-Z])[A-Za-z0-9]{32,35})$" wide //weight: 1
        $x_18_18 = "UNIC_KEY" wide //weight: 18
        $x_18_19 = "/create /sc MINUTE /mo 1 /tn" wide //weight: 18
        $x_18_20 = "//iplogger.org/" wide //weight: 18
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_18_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

