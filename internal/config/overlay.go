package config

import (
	"fmt"

	"github.com/pelletier/go-toml/v2"
)

// EnvConfigOverlay - путь к TOML-дополнению основного конфига. Панель 3X-UI
// пишет урезанный конфиг, а нодам нужны ещё свои разделы ([dc-pool],
// [secured], [stats.prometheus], [defense.*], [network.timeout] и т.п.).
// Окружение mtg наследует от процесса x-ui.
const EnvConfigOverlay = "MTG_CONFIG_OVERLAY"

// overlayUserKeys - разделы с пользователями. Из дополнения их не берём
// никогда: пользователи только из основного конфига (его пишет панель).
var overlayUserKeys = []string{"secret", "secrets", "secret-limits", "secret-ad-tags"}

// MergeOverlay сливает дополнение ПОД основной конфиг: ключ из основного
// всегда главнее, из дополнения берутся только отсутствующие ключи. Таблицы
// сливаются глубоко; массивы и значения не сливаются - побеждает основной.
func MergeOverlay(mainData, overlayData []byte) ([]byte, error) {
	mainTree := map[string]any{}
	if err := toml.Unmarshal(mainData, &mainTree); err != nil {
		return nil, fmt.Errorf("cannot parse toml config: %w", err)
	}

	overlayTree := map[string]any{}
	if err := toml.Unmarshal(overlayData, &overlayTree); err != nil {
		return nil, fmt.Errorf("cannot parse config overlay: %w", err)
	}

	for _, key := range overlayUserKeys {
		delete(overlayTree, key)
	}

	mergeUnder(mainTree, overlayTree)

	merged, err := toml.Marshal(mainTree)
	if err != nil {
		return nil, fmt.Errorf("cannot serialize merged config: %w", err)
	}

	return merged, nil
}

// mergeUnder добавляет в dst ключи из src, которых в dst нет. Если ключ есть
// в обоих и оба значения - таблицы, сливает их рекурсивно.
func mergeUnder(dst, src map[string]any) {
	for key, srcValue := range src {
		dstValue, ok := dst[key]
		if !ok {
			dst[key] = srcValue

			continue
		}

		dstTable, dstIsTable := dstValue.(map[string]any)
		srcTable, srcIsTable := srcValue.(map[string]any)

		if dstIsTable && srcIsTable {
			mergeUnder(dstTable, srcTable)
		}
	}
}
