#include <string.h>

struct Buffer {
    int data[4];
    int *cursor;
};

static int global_table[2][3] = {
    {1, 2, 3},
    {4, 5, 6},
};

static int global_flat[6] = {0};

int read_only_sum(const int arr[4]) {
    return arr[0] + arr[1] + arr[2] + arr[3];
}

void fill_with_index(int arr[static 4], int base) {
    for (int i = 0; i < 4; i++) {
        arr[i] = base + i;
    }
}

int write_through_offset(int *arr, int start) {
    int *p = arr + start;
    int old = *(p + 1);
    *(p + 2) = old + arr[0];
    return old;
}

int local_alias_chain(int arr[8], int index) {
    int *p = arr;
    int *q = p + index;
    q[0] = p[1] + arr[2];
    *(q + 1) = q[0] + p[3];
    return arr[index] + arr[index + 1];
}

int matrix_diag(int matrix[3][3]) {
    int sum = 0;
    for (int i = 0; i < 3; i++) {
        sum += matrix[i][i];
    }
    matrix[2][1] = sum;
    return matrix[2][1];
}

void cube_mix(int cube[2][3][4], int plane, int row, int col) {
    int (*plane_ref)[4] = cube[plane];
    int *row_ref = plane_ref[row];
    row_ref[col] = cube[0][1][2] + cube[1][2][3];
    cube[1][0][0] = row_ref[col] + plane_ref[0][1];
}

int struct_array_update(struct Buffer *buf, int idx) {
    int *p = buf->data;
    p[idx] = p[0] + buf->data[1];
    buf->cursor = p + idx;
    *(buf->cursor) = *(buf->cursor) + 5;
    return buf->data[idx];
}

int global_update(int idx, int value) {
    global_table[1][idx] = value;
    global_flat[idx] = global_table[1][idx] + global_table[0][idx];
    return global_flat[idx];
}

int bulk_ops(int dst[6], const int src[6]) {
    memcpy(dst, src, 6 * sizeof(int));
    memset(dst + 3, 0, 2 * sizeof(int));
    return dst[0] + dst[3] + dst[5];
}

int main() {
    int readonly[4] = {1, 3, 5, 7};
    int partial[8] = {2, 4, 6};
    int arr[8] = {8, 7, 6, 5, 4, 3, 2, 1};
    int copied[6] = {9, 8, 7, 6, 5, 4};
    int matrix[3][3] = {
        {1, 2, 3},
        {4, 5, 6},
        {7, 8, 9},
    };
    int cube[2][3][4] = {
        {
            {1, 2, 3, 4},
            {5, 6, 7, 8},
            {9, 10, 11, 12},
        },
        {
            {13, 14, 15, 16},
            {17, 18, 19, 20},
            {21, 22, 23, 24},
        },
    };
    struct Buffer buf = {{3, 1, 4, 1}, 0};

    int total = 0;
    total += read_only_sum(readonly);

    fill_with_index(partial, 10);
    total += partial[0] + partial[3];

    total += write_through_offset(arr, 2);
    total += local_alias_chain(arr, 3);

    total += matrix_diag(matrix);

    cube_mix(cube, 1, 2, 3);
    total += cube[1][0][0] + cube[1][2][3];

    total += struct_array_update(&buf, 2);
    total += buf.data[2];

    total += global_update(2, arr[4]);
    total += bulk_ops(global_flat, copied);

    int *local_escape = arr + 5;
    total += *local_escape;

    return total;
}
