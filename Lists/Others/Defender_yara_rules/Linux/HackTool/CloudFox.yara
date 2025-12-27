rule HackTool_Linux_CloudFox_A_2147946362_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CloudFox.A"
        threat_id = "2147946362"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CloudFox"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "aws/aws-sdk-go" ascii //weight: 2
        $x_2_2 = "mitchellh/mapstructure" ascii //weight: 2
        $x_2_3 = "bishopfox/knownawsaccountslookup" ascii //weight: 2
        $x_2_4 = "service/elasticloadbalancingv2" ascii //weight: 2
        $x_2_5 = "bsoncore.sortableString" ascii //weight: 2
        $x_2_6 = "aeadcrypter.S2AAEADCrypter" ascii //weight: 2
        $x_2_7 = "github.com/BishopFox/cloudfox/internal" ascii //weight: 2
        $x_2_8 = "zstd.betterFastEncoderDict" ascii //weight: 2
        $x_2_9 = "go.opencensus.io/stats/view.registerViewReq" ascii //weight: 2
        $x_2_10 = "s2a-go/internal/tokenmanager.singleTokenAccessTokenManager" ascii //weight: 2
        $x_2_11 = "awsservicemap" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

