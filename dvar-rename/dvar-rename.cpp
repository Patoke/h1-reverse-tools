#include <intrin.h>
#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>

union u_out_hash {
	uint32_t value;
	struct {
		uint8_t first;
		uint8_t second;
		uint8_t third;
		uint8_t fourth;
	};
};

constexpr u_out_hash generate_hash(const char* string)
{
	const char* v1;
	char v2, v6;
	int v4, v5, v7;
	char* end_ptr;

	v1 = string;
	v2 = *string;

	if (v2 == 48 && v1[1] == 120)
	{
		return u_out_hash(strtoul(v1 + 2, &end_ptr, 16));
	}

	v4 = v2;

	if ((v2 - 65) <= 0x19u)
	{
		v4 = v2 + 32;
	}

	v5 = 0xB3CB2E29 * static_cast<unsigned int>(v4 ^ 0x319712C3);

	if (v2)
	{
		do
		{
			v6 = *++v1;
			v7 = v6;
			if ((v6 - 65) <= 0x19u)
			{
				v7 = v6 + 32;
			}

			v5 = 0xB3CB2E29 * static_cast<unsigned int>(v5 ^ v7);
		} while (v6);
	}

	return u_out_hash(v5);
}

int main()
{
	std::vector<std::string> out_vars_vec{};
	out_vars_vec.reserve(4000);

	std::ifstream dvar_txt("dvars.txt", std::ios::binary);

	std::string line;
	while (std::getline(dvar_txt, line))
	{
		std::stringstream out_dvar{};
		out_dvar << std::hex << std::uppercase << std::setw(4) << std::setfill('0');

		line.erase(line.size() - 1);

		auto hash = generate_hash(line.data());
		out_dvar << std::format("{}|B9 {:02X} {:02X} {:02X} {:02X}", line.data(), hash.first, hash.second, hash.third, hash.fourth);

		out_vars_vec.emplace_back(out_dvar.str());
	}
    
	dvar_txt.close();

	std::ofstream out_vars("hashed.txt", std::ios::binary);

	for (auto& var : out_vars_vec)
		out_vars << var << "\n";

	out_vars.close();
}