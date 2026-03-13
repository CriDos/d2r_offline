#pragma once

#include <string_view>

namespace d2r_offline {

std::string_view OriginalPublicKeyPem();
std::string_view ReplacementPublicKeyPem();
std::string_view ReplacementPrivateKeyPem();

} // namespace d2r_offline
