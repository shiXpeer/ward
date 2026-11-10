package inventory

// UbuntuCodename reads the explicit release identity or recovers it from
// VERSION_ID on older Ubuntu releases whose os-release lacks VERSION_CODENAME.
func UbuntuCodename(release map[string]string) string {
	if release["ID"] != "ubuntu" {
		return ""
	}
	if name := release["VERSION_CODENAME"]; name != "" {
		return name
	}
	switch release["VERSION_ID"] {
	case "14.04":
		return "trusty"
	case "16.04":
		return "xenial"
	case "18.04":
		return "bionic"
	case "20.04":
		return "focal"
	case "22.04":
		return "jammy"
	case "24.04":
		return "noble"
	}
	return ""
}
