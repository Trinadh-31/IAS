import os

def make_samples():
    if not os.path.exists('sample_1mb.bin'):
        print('Creating sample_1mb.bin (1 MB)')
        with open('sample_1mb.bin','wb') as f:
            f.write(os.urandom(1024*1024))
    else:
        print('sample_1mb.bin already exists')
    if not os.path.exists('sample_10kb.bin'):
        print('Creating sample_10kb.bin (10 KB)')
        with open('sample_10kb.bin','wb') as f:
            f.write(os.urandom(10*1024))
    else:
        print('sample_10kb.bin already exists')

if __name__ == '__main__':
    make_samples()
