# DỰ TRỮ / THEO DÕI — phương án sau phản biện

## Các điểm đã chốt sau phản biện độc lập

- Dùng `ttk.Notebook` hai tab, bỏ splitter kéo MODEL/DỰ TRỮ; THEO DÕI tối đa 7 hàng và thanh cuộn khi màn hình thấp.
- Thanh trạng thái dùng chung nằm ngoài Notebook để lỗi/lưu/sao chép của tab Dự trữ không bị ẩn.
- Cùng đường DPAPI strict cho `spare_models` và `watch_keys`; bản ghi đang khóa không được gửi request, ciphertext không được mất khi sửa metadata.
- Mỗi watch có ID ngẫu nhiên bền vững và revision. Mỗi lô có run ID và cờ dừng; sửa/xóa/tắt Auto loại bỏ callback cũ.
- Watch chỉ gửi request theo key chính xác người dùng đã lưu, không gọi `inherit_key()`.
- Auto và thử tay dùng chung worker tuần tự, timeout 20 giây mỗi request. Auto chỉ nhắm `watch_keys`; vòng tự thử slot cũ bị bỏ.
- Sau hai lỗi xác thực/quyền truy cập 401/403 liên tiếp, tạm tắt Auto dòng đó và ghi lý do; lỗi mạng/429/5xx dùng backoff tối đa 60 phút, không gọi key chết.
- Không lưu raw provider body hoặc chuỗi exception có thể chứa secret. Kết quả có category và HTTP code riêng.
- Fit dựa theo nội dung Tổng quan, không theo requested width/height lớn nhất của tab ẩn. Test phải chọn tab Dự trữ trước thao tác bảng.
- Không thêm đường đưa THEO DÕI vào slot; chỉ có lưu độc lập và sao chép từ dự trữ/slot.

Phản biện là cổng thiết kế, không phải bằng chứng code đã đạt yêu cầu. Các mục trên phải được kiểm chứng bằng test và UI thực tế cô lập.

## Phạm vi người dùng yêu cầu

- Chuyển DỰ TRỮ khỏi dashboard sang tab riêng, dùng toàn vùng nội dung.
- Thay vị trí cũ bằng THEO DÕI, tối đa 7 key, không tìm kiếm.
- Auto thử chỉ chạy trên THEO DÕI. DỰ TRỮ giữ thử thủ công.
- Giữ mọi sửa lỗi UI đang có; không triển khai bản cũ trong lúc mở rộng phạm vi.

## Ranh giới bắt buộc

- Hai tab: Tổng quan (MODEL/VẬN HÀNH và THEO DÕI), Dự trữ (bảng và thao tác hiện có).
- DỰ TRỮ tiếp tục là danh sách model ứng viên, không phải danh sách key cần gửi request định kỳ.
- Mỗi dòng THEO DÕI là một credential có ID bền vững, tên gợi nhớ, endpoint, key và một model dùng để thử. Hai key khác nhau cùng endpoint/model không ghi đè nhau.
- UI và backend cùng chặn thêm dòng thứ 8; sửa dòng hiện có khi đủ 7 vẫn được phép.
- THEO DÕI không kế thừa key ngầm theo Base URL. Lấy từ dự trữ/slot là thao tác người dùng chọn rõ ràng và sao chép độc lập.
- Không tự đưa 7 dòng dự trữ đầu tiên vào THEO DÕI. Không tự bật lại Auto thử cũ vì tập mục tiêu đã đổi.
- Lưu, sửa, xóa, thử key và thêm vào THEO DÕI không ghi `ov.conf`, không chuyển slot, không khởi động lại server.
- Đưa vào slot tiếp tục đi qua `apply_conf_edit` và kiểm định hiện có; theo dõi thành công không đồng nghĩa provider an toàn.

## Đề xuất UX

- Hiển thị số lượng `0/7`, tên gợi nhớ, model thử, trạng thái gần nhất, độ trễ, lần thử và Auto theo từng dòng.
- Có nút thêm, sửa/double-click, thử ngay, tạm dừng và xóa có xác nhận; menu lấy từ dự trữ/slot theo lựa chọn rõ ràng.
- Auto có công tắc tổng mặc định tắt và trạng thái cho từng key. Chỉ chạy khi cả hai cho phép.
- Không hiện key thô trong bảng, log, tooltip hay chẩn đoán. Editor che key; copy theo cơ chế hết hạn clipboard hiện có.
- Kết quả thử là bằng chứng cho key + endpoint + model tại thời điểm thử, không kết luận toàn bộ model hay quota còn lại.
- 429 là giới hạn tần suất/quota, 401 là lỗi xác thực, 403 là quyền truy cập, 404 là endpoint/model, lỗi mạng/timeout không phải bằng chứng key hỏng.
- Thông báo chỉ khi đổi trạng thái để tránh lặp. Không thêm biểu đồ hoặc kho lịch sử lớn vào vòng này.

## Lịch thử và an toàn

- Tuần tự, một lô duy nhất, không chồng lô Auto và thử tay trên cùng watchlist.
- Chụp immutable snapshot ID + phiên bản credential trước khi gửi; bỏ kết quả trễ nếu dòng đã sửa/xóa.
- Timeout hữu hạn; cờ dừng chặn request tiếp theo. Tắt Auto không thể thu hồi request đã gửi.
- Dùng đồng hồ monotonic cho lịch; giãn chu kỳ khi 429 hoặc lỗi mạng và hiển thị lần thử kế tiếp.
- Request thử ngắn, nội dung giả, không đưa dữ liệu OpenViking vào request. UI giải thích request có thể tiêu token.
- `monitor.json` lưu danh sách mới riêng, áp DPAPI strict và giữ ciphertext nguyên vẹn khi key không đổi/đang khóa như DỰ TRỮ.

## Nền tảng và cổng xác minh

- Vòng `auto_probe_tick()` trước đây thử slot trong `ov.conf`, không thử `spare_models`; bản mới đã bỏ vòng này, chỉ có lịch riêng của THEO DÕI.
- `suite_bootstrap.py` trước đây không tự cô lập `USERPROFILE` khi chạy trực tiếp; test subprocess sentinel đã tái hiện lỗi, sau vá đã đạt `SUITE_ISOLATION_OK`.
- Runner với tính năng mới và hồi quy phản biện: 59/59 suite PASS, không skip/timeout. `SELF_CHECK_OK`; ma trận dashboard và slot editor đạt cả ba mức Tk scaling bên dưới.
- Hash/size/mtime của `ov.conf` và `monitor.json` không đổi qua các đợt test có guard. Chưa quy kết được nguồn ghi lịch sử bằng bằng chứng process/file-write.
- Ảnh cửa sổ Tk cô lập dùng dữ liệu giả cho cả hai tab: tối thiểu 3 hàng THEO DÕI đầy đủ, có cuộn đến hàng 7, toàn bộ nút Dự trữ đủ chỗ.

## Các phát hiện phản biện đã tái hiện và sửa

- Form Sửa chỉ gửi ID và trường người dùng nhập, không chép lại snapshot Auto cũ. Test mở form, nhận hai lỗi 401 trong lúc form còn mở rồi Lưu; trạng thái Auto tắt/lý do/lịch sử được giữ nguyên.
- Không nhận chuỗi `dpapi:` nhập trực tiếp qua watch store; người dùng nhập API key hoặc `${BIẾN_MÔI_TRƯỜNG}`. Ciphertext chỉ được xử lý qua đường load DPAPI strict.
- `watch_keys: null` được chuẩn hóa rỗng; dữ liệu hỏng kiểu/ID/credential/thời điểm khóa Auto và khóa lưu state, có cảnh báo nhưng không xóa hoặc ghi đè dữ liệu gốc. Không tự lọc mất key để làm test xanh.

## Cổng nghiệm thu dự kiến

- Tối đa 7, sửa khi đủ, hai key cùng endpoint/model, DPAPI locked, save failure, delete/edit trong lúc thử, stop/close, Auto tắt sau migration.
- DỰ TRỮ không Auto; không truy vấn provider khi chỉ mở tab, lưu hoặc tải state.
- UI có bề ngang 880/996/1020/1100/1400 tại Tk scaling 1.333333 / 1.666667 / 2.0 (Windows 100% / 125% / 150%); auto-fit chiều cao theo màn hình. Không tuyên bố Windows 200% từ Tk scaling 2.0. Tab DỰ TRỮ không chiếm chiều cao dashboard khi ẩn; bảng theo dõi không có thanh tìm kiếm.
- `ov.conf` không đổi sau toàn thao tác THEO DÕI; test profiles không ghi dữ liệu live.
- Phản biện độc lập trước triển khai; sync qua `scripts/monitor_sync.py` với backup/rollback sau khi đủ cổng.

## Đợt hoàn thiện thao tác và độ tin cậy

- Dự trữ có **Đưa sang Theo dõi** ở menu chuột phải và hàng nút. Chọn đúng một dòng, mở editor điền sẵn; chỉ Lưu mới thêm bản ghi độc lập. Giữ nguồn, không sao chép trạng thái thử/Auto, không kế thừa key ngầm. Dòng thiếu key/khóa DPAPI hoặc đủ bảy dòng bị chặn.
- Cài đặt lưu candidate trước, chỉ cập nhật shared state và tích hợp Windows sau khi ghi thành công; lỗi hiện trong hộp thoại và không làm thay đổi tùy chọn đang dùng.
- Ô Auto nhấp đúp không mở Sửa và không đảo hai lần. Auto dòng bật nhưng tổng tắt hiện **Chờ tổng**; lỗi xác thực thủ công không tạo thông báo tự tắt Auto giả.
- Kết quả quá `max(600, chu_kỳ_phút × 120)` giây được đánh dấu **Cũ**, không sửa bằng chứng đã lưu hoặc gửi thử thêm.
- Hộp lấy nguồn có grab; validation lỗi ở chính hộp thoại; thanh tiêu đề theo dark helper hiện có.
- Test recovery chỉ dùng bảy key giả: đóng/mở state, DPAPI, failed atomic replace, malformed-state lock, phục hồi bản backup và bảo toàn ciphertext; mạng/timeout/429/DPAPI locked không chạm provider thật.
- Tk scaling 2.666667 kiểm tra hệ số chữ tương đương Windows 200%, không thay cấu hình hiển thị Windows. Dashboard trên 150% có cuộn ngoài để tới Theo dõi; chiều rộng tối thiểu tăng theo DPI trong giới hạn màn hình. Slot editor giảm chiều cao danh sách model khi cần, không giấu nút. Cột ms/Lần thử/Auto đo theo giá trị thực và giữ minwidth đủ chữ.
- Kiểm chứng bản vá: runner cô lập đủ 64 suite PASS, không FAIL/SKIP/TIMEOUT; dashboard + slot editor tại bốn mức Tk 1.333333/1.666667/2.0/2.666667 đạt 8/8; self-check trả `SELF_CHECK_OK`. Ảnh fixture Tổng quan/Dự trữ dùng dữ liệu giả, không phải kết quả thử key thật.
- Hai lượt phản biện độc lập không có lỗi logic/bảo mật chặn triển khai. Các gợi ý căn hộp thoại, đo request width của nội dung Canvas và giảm repaint không thuộc cổng chặn; chưa tuyên bố đã sửa.
- Triển khai qua `monitor_sync.py`: receipt `applied`, 10 tệp nguồn/test, backup xác minh tại `monitor-sync-20261111T134101Z-f2944174`; đối chiếu lại không còn source drift. Cả `ov.conf` và `monitor.json` giữ nguyên SHA-256/size/mtime trong khoảng baseline triển khai, đồng bộ và mở bản live.
- GUI live PID 27504 hiển thị nút **Đưa sang Theo dõi** trong tab Dự trữ; Tổng quan vẫn 0/7 và Auto tắt. Không thử key thật hoặc thêm watch thật trong QA. Listener 19330/21434 giữ nguyên PID 7884/26176; `/health` và `/ready` cùng HTTP 200.

## Đợt khóa Cài đặt và tương tác sau `1d9cbc9`

- Cài đặt chỉ giữ một cửa sổ. Mở lại đưa form đang có lên trước và giữ nhập dở; sau đóng, form mới đọc shared state mới nhất.
- Lưu file thành công vẫn đi trước cập nhật RAM và tác dụng phụ Windows. `run_with_windows` là tùy chọn đã lưu; chỉ báo áp dụng khi lệnh PowerShell thành công và shortcut tồn tại, hoặc đã xác minh xóa. Nếu áp dụng lỗi, giữ form và cảnh báo **Đã lưu Cài đặt nhưng chưa áp dụng được Khởi động cùng Windows**; Lưu cho phép thử lại. Không giả định tùy chọn đã lưu đồng nghĩa Windows đã thực thi thành công.
- Shortcut tests dùng đường scratch dưới profile cô lập: mã lỗi shell, exit-zero không có file, unlink bị từ chối, retry và một vòng COM tạo/đọc lại tham số `--tray`/xóa thật. Không đổi Startup thật trong QA; không ghi raw shell output/exception vào app log.
- Nhấp đúp chỉ mở Sửa khi đúng vùng cell và có row ID; vùng heading/trống bỏ qua. Ô Auto vẫn đảo đúng một lần.
- Hộp Lấy từ căn giữa theo Monitor và kẹp trong primary-screen bounds. Virtual-screen/màn hình phụ chưa thuộc phạm vi kiểm chứng.
- Fit đo `overview_content` cộng scrollbar ở DPI cao, không đo request width của Canvas.
- Parent runner có `--runtime-helpers`: 68/68 PASS, không SKIP/FAIL/TIMEOUT. Ma trận dashboard, slot editor, Settings singleton, Settings apply/retry và source picker tại bốn mức Tk scaling 1.333333/1.666667/2.0/2.666667: 20/20 PASS. `SELF_CHECK_OK`; dữ liệu live giữ nguyên hash/size/mtime trong toàn khoảng kiểm thử.
- Phản biện độc lập `deleg_a48e8fd8`: không lỗi bảo mật/logic chặn, 66 PASS + 2 helper SKIP vì không bật opt-in; riêng ma trận DPI 20/20 PASS. Không gộp SKIP của reviewer thành PASS.
- Ảnh hộp Cài đặt khi lỗi áp dụng và source picker tại Tk 2.666667 đã kiểm tra trực quan bằng dữ liệu giả: nút, checkbox và cảnh báo đủ chữ, không cắt khung.

## Khóa ghi khi không đọc được toàn file state

- `monitor.json` chưa tồn tại được phép tạo ở lần chạy đầu. File tồn tại nhưng lỗi đọc, UTF-8, JSON hoặc root không phải object phải khóa lưu; không dùng mặc định rỗng để ghi đè.
- Lỗi toàn file trả state an toàn với Auto tắt, cờ `_state_load_error` và thông báo cố định. `save_state` chặn cờ này trước khi tạo thư mục, mã hóa hoặc gọi writer; startup auto-fit, Settings, Watch và thoát không được ghi file gốc.
- Banner cảnh báo riêng luôn hiện và xuống dòng theo cửa sổ; thay đổi trạng thái thao tác không xóa cảnh báo. Cài đặt hiển thị cùng hướng dẫn và không áp dụng Windows/RAM khi lưu thất bại.
- Khôi phục: đóng Monitor, giữ lại file hỏng, khôi phục `monitor.json` hợp lệ từ bản sao lưu riêng rồi mở lại. Backup `monitor-sync-*` chỉ chứa nguồn, không chứa state; không tự đặt lại mặc định hay suy đoán credential.
- Kiểm thử chỉ dùng dữ liệu giả và guard filesystem/network. Không thử sửa, đọc nội dung hoặc khôi phục state live để tái hiện lỗi này.

## Chống ghi đè state thay đổi sau khi nạp

- `load_state()` đọc raw bytes, giải mã UTF-8 rồi lưu SHA-256 vào `_state_revision` trong RAM; không chuẩn hóa CRLF trước khi tính hash. File thực sự chưa có dùng revision `None`. Revision do nội dung JSON tự khai báo không được tin.
- `save_state()` so sánh revision của candidate với file hiện tại bên trong `.monitor-state.lock`, ngay trước writer. File mới xuất hiện, bị xóa, đổi byte, bị hỏng hoặc không xác minh được đều chặn ghi. Chỉ own save thành công mới tiến revision; lỗi writer không được tự nhận file mới làm baseline.
- Các luồng GUI đi qua `save_runtime_state()`: sau own save truyền revision mới về shared state; khi xung đột đặt `_state_revision_error`, tắt Auto, hủy công việc Watch chưa gửi và hiển thị banner/Settings bền vững. Settings, Watch, Reserve và cache chỉ áp dụng candidate sau khi lưu thành công; startup/thoát cũng không ghi đè state ngoài.
- Khôi phục yêu cầu đóng/mở lại Monitor để nạp file đã được người dùng xác nhận. Không tự hợp nhất credential, không tự đặt lại mặc định, không tự mở khóa khi file cũ xuất hiện lại.
- Phạm vi đảm bảo: phát hiện drift đã xảy ra tại lần kiểm tra trước khi ghi, và tuần tự hóa writer cùng dùng khóa. Writer ngoài bỏ qua khóa vẫn có thể đua trong khoảng kiểm tra–replace; không tuyên bố filesystem compare-and-swap hoặc chặn được mọi công cụ chỉnh file.
- Chỉ triển khai mục revision guard trong đợt này. Backup state tự động, runner DPI/CI và multi-monitor không thuộc phạm vi.

## Kết quả nghiệm thu bản hai tab ban đầu

- Phản biện xác nhận ba lỗi race/DPAPI/state: `passed=true`, không có lỗi logic hoặc bảo mật chặn. Gợi ý UX không được xem là bằng chứng lỗi đã sửa.
- Đối chiếu runner: đủ 59 suite, 59 PASS, không FAIL/SKIP/TIMEOUT. Chạy lại dashboard và slot editor tại cả ba mức Tk scaling nêu trên: 6/6 PASS; self-check đạt `SELF_CHECK_OK`.
- Đồng bộ source-only qua `monitor_sync.py`: receipt `applied`, backup xác minh hợp lệ, kế hoạch sau sync không còn drift. Không ghi đè `ov.conf` hoặc `monitor.json` trong bước triển khai.
- Mở bản live và chuyển qua lại hai tab: THEO DÕI trống 0/7, Auto tắt; DỰ TRỮ toàn chiều rộng, không Auto, hai hàng nút hiển thị đủ. Không thử key thật trong lượt QA.
- Phân biệt mốc dữ liệu: hai file dữ liệu nguyên byte qua bước source sync; sau khởi động GUI, `monitor.json` có thay đổi trạng thái migration/autofit. `ov.conf` vẫn nguyên SHA-256 và mtime. Không dùng hash để khẳng định mọi trường state hoặc key không đổi khi không có bản so sánh nội dung.
- Giữ nguyên PID OpenViking/AGFS, `/health` và `/ready` cùng HTTP 200; chỉ tiến trình Monitor được mở mới.
