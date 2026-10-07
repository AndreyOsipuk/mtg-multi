package mtglib

import (
	"net"
	"time"
)

// Дробление ServerHello FakeTLS (client-mss). ТСПУ узнаёт mtg по ServerHello,
// ушедшему крупными сегментами, а мелкими (как при MSS 92 у клиента) - нет.
// Держать маленький MSS всю сессию нельзя (медленно, лишние pps), поэтому
// мелко режется только ServerHello, остальное идёт полноразмерными сегментами.
//
// Почему не «маленький MSS на слушающем сокете, потом setsockopt TCP_MAXSEG
// побольше»: Linux фиксирует mss_clamp в рукопожатии как min(MSS клиента,
// TCP_MAXSEG сокета), а setsockopt на установленном соединении меняет только
// user_mss и на размер отправляемых сегментов уже не влияет (проверено: после
// listener MSS 92 и setsockopt 1400 tcpi_snd_mss так и остаётся 80). Временно
// уменьшить MSS установленного соединения тоже нельзя по той же причине.
//
// Поэтому ServerHello пишется кусками размером в полезную нагрузку сегмента
// при client-mss, и каждый следующий кусок - только когда предыдущий ушёл в
// сеть (tcpi_notsent_bytes = 0). Иначе куски, упёршиеся в окно перегрузки или
// автокорк, ядро склеит в один большой сегмент: на RTT 100 мс 4 КБ кусками
// по 80 байт без ожидания уходят 13 сегментами, с ожиданием - 52.

// fragmentedWriter пишет ServerHello кусками по mss (см. writeFragmented).
type fragmentedWriter struct {
	conn     net.Conn
	mss      int
	deadline time.Time
}

func (w fragmentedWriter) Write(p []byte) (int, error) {
	return writeFragmented(w.conn, p, w.mss, w.deadline)
}
